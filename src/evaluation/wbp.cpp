#include "evaluation/wbp.hpp"
#include <sodium.h>
#include <algorithm>
#include <stdexcept>
namespace ppkr::evaluation::wbp {
using crypto::view;
namespace {
void require(bool b){if(!b)throw std::runtime_error("WBP correctness failure");}
bool equal(const Key& a,const Key& b){return sodium_memcmp(a.data(),b.data(),a.size())==0;}
Key hash(const Bytes& input){std::array<unsigned char,64> h{};crypto_hash_sha512(h.data(),input.data(),input.size());Key k{};std::copy_n(h.begin(),32,k.begin());return k;}
Key xor_key(const Key& a,const Key& b){Key x{};for(std::size_t i=0;i<x.size();++i)x[i]=a[i]^b[i];return x;}
std::vector<Bytes> decode(const Bytes& bytes){
  std::vector<Bytes> f;std::size_t pos=0;
  while(pos<bytes.size()){
    require(bytes.size()-pos>=8);std::uint64_t len=0;
    for(int i=0;i<8;++i)len=(len<<8)|bytes[pos++];
    require(len<=bytes.size()-pos);f.emplace_back(bytes.begin()+pos,bytes.begin()+pos+len);pos+=len;
  }return f;
}
Keys keys(const Bytes& ikm,const Bytes& salt,std::string_view domain){
  const Bytes info(domain.begin(),domain.end());const auto out=hkdf(ikm,salt,info,96);Keys k{};
  std::copy_n(out.begin(),32,k.first.begin());std::copy_n(out.begin()+32,32,k.second.begin());std::copy_n(out.begin()+64,32,k.third.begin());return k;
}
Keys password_keys(const Key& y,const Key& nonce){return keys(crypto::bytes(y),crypto::bytes(nonce),"WBP/KDF1");}
Keys session_keys(const oprf::Point& a,const oprf::Point& b,const oprf::Point& c,const Bytes& pre){
  Bytes ikm;ikm.insert(ikm.end(),a.begin(),a.end());ikm.insert(ikm.end(),b.begin(),b.end());ikm.insert(ikm.end(),c.begin(),c.end());
  return keys(ikm,crypto::bytes(hash(pre)),"WBP/KDF2");
}
Bytes preamble(const Request& q,const Reply& r,const oprf::Point& server_public){
  return crypto::encode({view(q.a),view(q.nonce),view(q.ephemeral.pk),view(server_public),view(r.masked),view(r.nonce),view(r.tag),view(r.b),view(r.server_nonce),view(r.ephemeral)});
}
Bytes client_mac_message(const Bytes& pre,const Key& ts){
  Bytes joined=pre;joined.insert(joined.end(),ts.begin(),ts.end());return crypto::bytes(hash(joined));
}
// Every actual C-S / S-H hop is encoded separately: aid changes relay headers.
void hop(Traffic* t,const Bytes& m){if(t){++t->server_messages;t->server_bytes+=m.size();}}
Bytes counter_bytes(std::uint64_t n){Bytes out(8);for(int i=0;i<8;++i)out[7-i]=(n>>(8*i))&255;return out;}
}
Key mac(std::string_view key,const Bytes& m){
  crypto_auth_hmacsha256_state s;Key tag{};
  crypto_auth_hmacsha256_init(&s,reinterpret_cast<const unsigned char*>(key.data()),key.size());
  crypto_auth_hmacsha256_update(&s,m.data(),m.size());crypto_auth_hmacsha256_final(&s,tag.data());return tag;
}
Bytes hkdf(const Bytes& ikm,const Bytes& salt,const Bytes& info,std::size_t length){
  if(length>255*32)throw std::invalid_argument("HKDF output too long");
  const auto prk=mac(view(salt),ikm);Bytes out,previous;
  for(std::size_t i=1;out.size()<length;++i){
    Bytes m=previous;m.insert(m.end(),info.begin(),info.end());m.push_back(static_cast<unsigned char>(i));
    const auto block=mac(view(prk),m);previous.assign(block.begin(),block.end());
    const auto take=std::min(length-out.size(),block.size());out.insert(out.end(),block.begin(),block.begin()+take);
  }return out;
}
DhKeys dh_keygen(){DhKeys k{};k.sk=oprf::random_scalar();require(crypto_scalarmult_ristretto255_base(k.pk.data(),k.sk.data())==0);return k;}
oprf::Point dh(const oprf::Scalar& sk,const oprf::Point& pk){
  if(!crypto_core_ristretto255_is_valid_point(pk.data())||sodium_is_zero(pk.data(),pk.size()))throw std::invalid_argument("invalid DH public key");
  oprf::Point out{};if(crypto_scalarmult_ristretto255(out.data(),sk.data(),pk.data())!=0)throw std::invalid_argument("DH failed");return out;
}
void Workload::initialize(Traffic* t){
  pending.reset();recovered.reset();
  const auto key=crypto::random_key();const auto client=dh_keygen();const auto blind=oprf::random_scalar();
  // Figure 4's OPRF input is pw only, not (pw, ID_C).
  const auto a=oprf::hsm_blind(config.password,blind);
  if(t)hop(t,crypto::encode({"Init",config.id,view(a)}));
  const auto old=account;Key aid{};do{aid=crypto::random_key();}while(tombstones.count(aid));account=aid;
  if(t)hop(t,crypto::encode({"Init",view(aid),old?view(*old):std::string_view{},view(a)}));
  if(old)tombstones.insert(*old);
  record.reset();tombstones.insert(aid);
  const auto k=oprf::random_scalar();const auto b=oprf::hsm_evaluate(a,k);const auto n1=crypto::random_key();
  const auto signed_message=crypto::encode({view(b),view(n1)});
  Signature sig{};if(concrete_attestation)sig=crypto::sign(signed_message,server_sig);
  const auto signature=concrete_attestation?view(sig):std::string_view{};
  if(t){hop(t,crypto::encode({view(aid),view(b),view(n1),signature}));hop(t,crypto::encode({view(b),view(n1),signature}));}
  const auto tr_h=hash(crypto::encode({view(a),view(b),view(n1)}));
  if(concrete_attestation)require(crypto::verify(signed_message,sig,server_sig.pk));
  const auto y=oprf::hsm_finalize(config.password,b,blind);const auto ne=crypto::random_key();const auto derived=password_keys(y,ne);
  const auto masked=xor_key(client.sk,derived.second);
  const auto te=mac(view(derived.third),crypto::encode({view(server_dh.pk),view(ne),view(masked)}));
  const auto tr_c=hash(crypto::encode({view(a),view(b),view(n1)}));
  const auto env=crypto::ae_encrypt(crypto::bytes(key),derived.first);
  const auto upload=crypto::pke_encrypt(crypto::encode({view(env),view(tr_c),view(client.pk),view(masked),view(ne),view(te)}),server_enc.pk);
  if(t){hop(t,crypto::encode({"File",view(upload)}));hop(t,crypto::encode({"File",view(aid),view(upload)}));}
  const auto plaintext=crypto::pke_decrypt(upload,server_enc);require(plaintext.has_value());const auto f=decode(*plaintext);
  require(f.size()==6&&f[1]==crypto::bytes(tr_h));
  record=Record{aid,k,f[0],crypto::key_from_bytes(f[2]),crypto::key_from_bytes(f[3]),crypto::key_from_bytes(f[4]),crypto::key_from_bytes(f[5]),10};
  if(t)hop(t,crypto::encode({"InitRes",view(aid),std::string_view("\1",1)}));
  original=key;
}
Request Workload::client_start(std::string_view password)const{
  const auto r=oprf::random_scalar();const auto a=oprf::hsm_blind(password,r);
  return {r,a,crypto::random_key(),dh_keygen()};
}
std::optional<Reply> Workload::hsm_start(const Request& q){
  pending.reset();if(!record||!account||*account!=record->aid)return std::nullopt;
  if(record->counter==0){record.reset();return std::nullopt;}--record->counter;
  const auto b=oprf::hsm_evaluate(q.a,record->oprf_key);const auto nonce=crypto::random_key();const auto eph=dh_keygen();
  Reply reply{b,record->masked,record->nonce,record->tag,nonce,eph.pk,{},{}};
  const auto pre=preamble(q,reply,server_dh.pk);
  const auto k=session_keys(dh(eph.sk,q.ephemeral.pk),dh(server_dh.sk,q.ephemeral.pk),dh(eph.sk,record->client_public),pre);
  reply.signature=concrete_attestation?crypto::sign(crypto::encode({view(b)}),server_sig):Signature{};
  const auto ts=mac(view(k.first),crypto::bytes(hash(pre)));
  reply.server_tag=ts;
  pending=Pending{k.second,k.third,ts,pre};return reply;
}
std::optional<Proof> Workload::client_authenticate(std::string_view password,const Request& q,const Reply& r)const{
  if(concrete_attestation&&!crypto::verify(crypto::encode({view(r.b)}),r.signature,server_sig.pk))return std::nullopt;
  const auto y=oprf::hsm_finalize(password,r.b,q.blind);const auto k=password_keys(y,r.nonce);
  const auto te=mac(view(k.third),crypto::encode({view(server_dh.pk),view(r.nonce),view(r.masked)}));
  if(!equal(te,r.tag))return std::nullopt;
  const auto sk=xor_key(r.masked,k.second);const auto pre=preamble(q,r,server_dh.pk);
  const auto session=session_keys(dh(q.ephemeral.sk,r.ephemeral),dh(q.ephemeral.sk,server_dh.pk),dh(sk,r.ephemeral),pre);
  const auto ts=mac(view(session.first),crypto::bytes(hash(pre)));
  if(!equal(ts,r.server_tag))return std::nullopt;
  return Proof{mac(view(session.second),client_mac_message(pre,ts)),k.first,session.third};
}
std::optional<Bytes> Workload::hsm_finish(const Key& tag){
  if(!pending||!record)return std::nullopt;
  const auto state=*pending;pending.reset();
  if(!equal(tag,mac(view(state.client_mac),client_mac_message(state.preamble,state.server_tag))))return std::nullopt;
  record->counter=10;return crypto::ae_encrypt(record->envelope,state.session_key);
}
bool Workload::client_finish(const Proof& proof,const Bytes& c){
  recovered.reset();const auto env=crypto::ae_decrypt(c,proof.session_key);if(!env)return false;
  const auto key=crypto::ae_decrypt(*env,proof.export_key);if(!key||key->size()!=32)return false;
  recovered=crypto::key_from_bytes(*key);return true;
}
bool Workload::recover(std::string_view password,Traffic* t){
  recovered.reset();const auto q=client_start(password);
  if(t){hop(t,crypto::encode({"Rec",config.id,view(q.nonce),view(q.ephemeral.pk),view(q.a)}));if(account)hop(t,crypto::encode({"Rec",view(*account),view(q.nonce),view(q.ephemeral.pk),view(q.a)}));}
  const auto r=hsm_start(q);if(!r)return false;
  const auto sig=concrete_attestation?view(r->signature):std::string_view{};
  if(t){hop(t,crypto::encode({view(*account),view(r->b),view(r->masked),view(r->nonce),view(r->tag),view(r->server_nonce),view(r->ephemeral),view(r->server_tag),sig}));hop(t,crypto::encode({view(r->b),view(r->masked),view(r->nonce),view(r->tag),view(r->server_nonce),view(r->ephemeral),view(r->server_tag),sig}));}
  const auto proof=client_authenticate(password,q,*r);if(!proof)return false;
  if(t){hop(t,crypto::encode({"RecAuth",view(proof->tag)}));hop(t,crypto::encode({"RecAuth",view(*account),view(proof->tag)}));}
  const auto ciphertext=hsm_finish(proof->tag);if(!ciphertext)return false;
  if(t){hop(t,crypto::encode({view(*account),view(*ciphertext)}));hop(t,crypto::encode({view(*ciphertext)}));}
  return client_finish(*proof,*ciphertext);
}
void Workload::setup(Stage s){if(s==Stage::KeyRecovery)initialize();else if(s!=Stage::Initialization)throw std::invalid_argument("WBP has Init/Rec only");}
void Workload::run(Stage s,Traffic* t){if(s==Stage::Initialization)initialize(t);else if(s==Stage::KeyRecovery)require(recover(config.password,t));else throw std::invalid_argument("WBP has Init/Rec only");}
void Workload::validate(Stage s)const{require(original.has_value()&&record.has_value()&&account==record->aid&&record->counter==10);if(s==Stage::KeyRecovery)require(recovered==original);}
Storage Workload::storage(Stage)const{
  require(record.has_value()&&account.has_value());Storage s;const auto& r=*record;const auto ctr=counter_bytes(r.counter);
  s.hsm=crypto::encode({"HSMRecord",view(r.aid),view(r.oprf_key),view(r.envelope),view(r.client_public),view(r.masked),view(r.nonce),view(r.tag),view(ctr)}).size();
  s.account_mapping=crypto::encode({"AccountRecord",config.id,view(*account)}).size();s.client_output=32;return s;
}
}
