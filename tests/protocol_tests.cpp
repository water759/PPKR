#include "protocol/core.hpp"
#include <iostream>
#include <stdexcept>
#include <functional>
using namespace ppkr;
using namespace ppkr::protocol;
namespace {
int checks=0;
void check(bool value) { ++checks; if(!value) throw std::runtime_error("check "+std::to_string(checks)+" failed"); }
template<class F> void reject(F f) { bool bad=false; try { f(); } catch(const std::invalid_argument&) {bad=true;} check(bad); }
struct Fixture {
  Device d; Hsm h; Server s; std::string id="alice"; std::string pw="correct password"; Key original{};
  Fixture() {
    auto [pending,request]=d.begin_init(id,pw);
    check(d.records.empty() && h.records.empty());
    auto response=s.relay(h.begin_init(s.relay(request)));
    auto upload=d.finish_init_crypto(pending,response);
    check(d.records.empty() && h.records.empty());
    auto result=s.relay(h.accept_init(id,s.relay(upload),100));
    auto key=d.accept_init(pending,result,100); check(key.has_value()); original=*key;
    check(d.records.count(id)==1 && h.records.count(id)==1);
    const auto x=oprf::encode_input(pw,id);
    auto derived=crypto::derive(oprf::device_evaluate(x,d.records.at(id).key),oprf::hsm_direct(x,h.records.at(id).key));
    check(derived.signing.pk==h.records.at(id).pk_c);
    auto mk=crypto::ae_decrypt(h.records.at(id).cmk,derived.kek); check(mk && mk->size()==32);
    check(crypto::ae_decrypt(h.records.at(id).cf,crypto::key_from_bytes(*mk))==crypto::bytes(original));
    check(d.records.at(id).window.counter==0 && h.records.at(id).window.counter==0);
  }
  std::optional<Key> recover(std::string_view password,Time now=101) {
    auto begin=d.begin_recovery(id,password,now); if(!begin) return std::nullopt;
    auto [pending,request]=std::move(*begin);
    auto response=h.begin_recovery(s.relay(request),now); if(!response) return std::nullopt;
    auto auth=d.authenticate(pending,s.relay(*response)); if(!auth) return std::nullopt;
    auto result=s.relay(h.authenticate(id,s.relay(*auth)));
    return d.recover(pending,result);
  }
};
std::string hex(const Key& key) {
  const char* digits="0123456789abcdef"; std::string out;
  for(auto b:key) { out+=digits[b>>4]; out+=digits[b&15]; } return out;
}
void primitives() {
  Key d{},h{}; for(int i=0;i<32;++i) {d[i]=i;h[i]=32+i;}
  // hashlib SHA-512 reference vectors; Ed25519 public key obtained from sodium.
  check(hex(crypto::hash_root({"root",crypto::view(d),crypto::view(h)}))=="2c337c95f4e521f3c31106aecf1dea16aa04692ea4b6b170f9c3348480f597ce");
  auto derived=crypto::derive(d,h);
  check(hex(derived.kek)=="ea0daabd79e793e7b7f84c871fd549528e57a8ae09c861eec30fc781746ddb76");
  check(hex(derived.signing.pk)=="9bf5cf578ea1d91d344711f58bcb2205086faf575b95c9b8060c2833fcdf0784");
  auto key=crypto::random_key(), wrong=key; wrong[0]^=1;
  for(std::size_t size:{0,1,32,1024}) {
    crypto::Bytes msg(size,0x42); auto c=crypto::ae_encrypt(msg,key);
    check(crypto::ae_decrypt(c,key)==msg); check(!crypto::ae_decrypt(c,wrong));
    c.back()^=1; check(!crypto::ae_decrypt(c,key));
    auto enc=crypto::encryption_keygen(), other=crypto::encryption_keygen();
    auto sealed=crypto::pke_encrypt(msg,enc.pk);
    check(crypto::pke_decrypt(sealed,enc)==msg); check(!crypto::pke_decrypt(sealed,other));
    sealed.back()^=1; check(!crypto::pke_decrypt(sealed,enc));
  }
  check(!crypto::ae_decrypt({},key)); check(!crypto::pke_decrypt({},crypto::encryption_keygen()));
  auto signing=crypto::signing_from_seed(key); check(signing.pk==crypto::signing_from_seed(key).pk);
  auto msg=crypto::encode({"test",std::string_view("binary\0value",12)}); auto signature=crypto::sign(msg,signing);
  check(signature==crypto::sign(msg,signing)); check(crypto::verify(msg,signature,signing.pk));
  msg[0]^=1; check(!crypto::verify(msg,signature,signing.pk));
  signature[0]^=1; check(!crypto::verify(crypto::encode({"test",std::string_view("binary\0value",12)}),signature,signing.pk));
  check(crypto::hash_root({"a","bc"})!=crypto::hash_root({"ab","c"}));
  check(crypto::hash_root({"x"})!=crypto::hash_kek({"x"}));
}
void honest() {
  for(int i=0;i<20;++i) {
    Fixture f; auto recovered=f.recover(f.pw); check(recovered==f.original);
    check(f.d.records.at(f.id).window.counter==1 && f.h.records.at(f.id).window.counter==0);
    Client c; auto delivery=deliver_key(*recovered,c.qr_public_key());
    check(c.receive(delivery)==f.original);
    Client other; check(!other.receive(delivery)); delivery.back()^=1; check(!c.receive(delivery));
    check(f.recover(f.pw)==f.original);
    check(!f.recover("wrong password"));
    check(f.h.records.at(f.id).window.counter==1);
    check(f.recover(f.pw)==f.original);
  }
  Device d; Hsm h; Server s;
  for(const auto& id:{std::string(""),std::string("用户"),std::string("a\0b",3)}) {
    auto [p,q]=d.begin_init(id,std::string("p\0w",3));
    auto response=h.begin_init(q); auto upload=d.finish_init_crypto(p,response);
    auto original=d.accept_init(p,h.accept_init(id,upload,10),10); check(original.has_value());
    auto start=d.begin_recovery(id,std::string("p\0w",3),11); check(start.has_value());
    auto [r,request]=std::move(*start); auto reply=h.begin_recovery(request,11); check(reply.has_value());
    auto auth=d.authenticate(r,*reply); check(auth.has_value());
    check(d.recover(r,h.authenticate(id,*auth))==original);
  }
  reject([&]{d.begin_init("","");});
  check(!d.begin_recovery("missing","pw",12));
  check(!h.begin_recovery({oprf::hash_to_group(oprf::Domain::Hsm,"x"),"missing"},12));
}
void alterations() {
  // Each branch starts from a fresh honest initialization; no retry semantics added.
  for(int which=0;which<7;++which) {
    Fixture f; auto [p,request]=*f.d.begin_recovery(f.id,f.pw,101);
    auto response=*f.h.begin_recovery(request,101);
    if(which==0) response.nonce[0]^=1;
    if(which==1) response.b=oprf::hash_to_group(oprf::Domain::Hsm,"altered reply");
    if(which==2) response.cmk.back()^=1;
    if(which==3) {response.id="other"; check(!f.d.authenticate(p,response)); continue;}
    auto auth=f.d.authenticate(p,response); check(auth.has_value());
    if(which==4) auth->signature[0]^=1;
    if(which==5) f.h.records.at(f.id).pk_c=crypto::random_key();
    auto result=f.h.authenticate(f.id,*auth);
    if(which==6) {check(result.success); result.ciphertext->back()^=1;}
    if(which==0 || which==1 || which==4 || which==5) {
      check(!result.success && !result.ciphertext); check(f.h.records.at(f.id).window.counter==1);
    }
    if(which==2) check(result.success); // cmk isn't in RecAuth: AE detects corruption later.
    check(!f.d.recover(p,result));
    check(!f.h.authenticate(f.id,*auth).success);
  }
  // Every field in the specified RecAuth tuple is bound to the signature.
  const auto k=crypto::signing_from_seed(crypto::random_key());
  auto a=oprf::hash_to_group(oprf::Domain::Hsm,"a"), b=oprf::hash_to_group(oprf::Domain::Hsm,"b");
  auto nonce=crypto::random_key(); auto signature=crypto::sign(authentication_message(a,b,"id",nonce),k);
  auto different=oprf::hash_to_group(oprf::Domain::Hsm,"c");
  check(!crypto::verify(authentication_message(different,b,"id",nonce),signature,k.pk));
  check(!crypto::verify(authentication_message(a,different,"id",nonce),signature,k.pk));
  check(!crypto::verify(authentication_message(a,b,"id2",nonce),signature,k.pk));
  nonce[0]^=1; check(!crypto::verify(authentication_message(a,b,"id",nonce),signature,k.pk));
  Fixture f; auto [p,q]=*f.d.begin_recovery(f.id,f.pw,101);
  auto response=*f.h.begin_recovery(q,101); auto auth=*f.d.authenticate(p,response);
  const auto success=f.h.authenticate(f.id,auth);
  check(f.d.recover(p,success)==f.original);
  check(!f.d.recover(p,success));
  check(!f.d.authenticate(p,response));
  auto [next,next_request]=*f.d.begin_recovery(f.id,f.pw,102);
  check(f.h.begin_recovery(next_request,102).has_value());
  check(!f.h.authenticate(f.id,auth).success); // Fresh n_H invalidates old signature.
}
void init_failures() {
  for(int kind=0;kind<4;++kind) {
    Device d; Hsm h; auto [p,q]=d.begin_init("id","pw"); auto response=h.begin_init(q);
    if(kind==0) { response.id="other"; reject([&]{d.finish_init_crypto(p,response);}); continue; }
    auto upload=d.finish_init_crypto(p,response);
    if(kind==1) upload.ciphertext.back()^=1;
    if(kind==2) upload.ciphertext=crypto::pke_encrypt(crypto::encode({"invalid"}),response.pk_enc);
    if(kind==3) upload.ciphertext=crypto::pke_encrypt(crypto::encode({"a","b","short pk"}),response.pk_enc);
    auto result=h.accept_init("id",upload,100); check(!result.success);
    check(!d.accept_init(p,result,100)); check(d.records.empty() && h.records.empty());
    check(!h.accept_init("id",upload,100).success);
  }
}
void windows() {
  Fixture f; f.d.policy={10,2}; f.h.policy={10,2};
  check(!f.recover("wrong",101)); check(!f.recover("wrong",102));
  check(f.d.records.at(f.id).window.counter==2 && f.h.records.at(f.id).window.counter==2);
  check(!f.d.begin_recovery(f.id,f.pw,109));
  auto a=oprf::hash_to_group(oprf::Domain::Hsm,"test"); check(!f.h.begin_recovery({a,f.id},109));
  check(f.recover(f.pw,110)==f.original);
  check(f.d.records.at(f.id).window.counter==1 && f.h.records.at(f.id).window.counter==0);
  check(f.d.records.at(f.id).window.start==110 && f.h.records.at(f.id).window.start==110);
  reject([&]{f.d.begin_recovery(f.id,f.pw,109);});
}
}
int main() {
  try { oprf::initialize(); primitives(); honest(); alterations(); init_failures(); windows();
    std::cout<<"PASS: "<<checks<<" initialization/recovery/primitive checks\n"; return 0;
  } catch(const std::exception& e) { std::cerr<<"FAIL: "<<e.what()<<'\n'; return 1; }
}
