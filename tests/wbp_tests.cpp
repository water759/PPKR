#include "evaluation/wbp.hpp"
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <iostream>
#include <stdexcept>
using namespace ppkr::evaluation;
namespace {
ppkr::crypto::Bytes hex(const std::string& s){ppkr::crypto::Bytes b;for(std::size_t i=0;i<s.size();i+=2)b.push_back(std::stoul(s.substr(i,2),nullptr,16));return b;}
}
int main(){try{
 ppkr::oprf::initialize();int checks=0;
 auto check=[&](bool b){++checks;if(!b)throw std::runtime_error("WBP check "+std::to_string(checks)+" failed");};
 // RFC 5869 test case 1, SHA-256, including a partial final block.
 const ppkr::crypto::Bytes ikm(22,0x0b),salt=hex("000102030405060708090a0b0c"),info=hex("f0f1f2f3f4f5f6f7f8f9");
 check(wbp::hkdf(ikm,salt,info,42)==hex("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"));
 // Independent OpenSSL HMAC reference.
 ppkr::crypto::Key expected_mac{};unsigned int mac_len=0;
 HMAC(EVP_sha256(),salt.data(),salt.size(),ikm.data(),ikm.size(),expected_mac.data(),&mac_len);
 check(mac_len==32&&wbp::mac(ppkr::crypto::view(salt),ikm)==expected_mac);
 bool rejected=false;try{wbp::hkdf({}, {}, {},8161);}catch(const std::invalid_argument&){rejected=true;}check(rejected);
 const auto x=wbp::dh_keygen(),y=wbp::dh_keygen();check(wbp::dh(x.sk,y.pk)==wbp::dh(y.sk,x.pk));
 rejected=false;try{wbp::dh(x.sk,{});}catch(const std::invalid_argument&){rejected=true;}check(rejected);
 ppkr::oprf::Scalar one{};one[0]=1;const auto base=ppkr::crypto::key_from_bytes(hex("e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76"));check(wbp::dh(one,base)==base);
 for(bool attested:{false,true}){
  for(auto stage:{Stage::Initialization,Stage::KeyRecovery}){
   wbp::Workload w({},attested);w.setup(stage);Traffic t;w.run(stage,&t);w.validate(stage);
   check(t.server_messages==(stage==Stage::Initialization?7:8));check(t.relayed_messages==0&&t.direct_messages==0);
   const auto st=w.storage(stage);check(st.device==0&&st.hsm>256&&st.account_mapping>32&&st.client_output==32);
   wbp::Workload again({},attested);again.setup(stage);Traffic t2;again.run(stage,&t2);again.validate(stage);check(t.ordinary_bytes()==t2.ordinary_bytes());
  }
  wbp::Workload w({},attested);check(!w.recover("0123456789abcdef"));w.initialize();
  check(!w.recover("wrong"));check(w.record->counter==9);check(w.recover("0123456789abcdef"));w.validate(Stage::KeyRecovery);
  check(w.record->counter==10);
  auto q=w.client_start("0123456789abcdef");auto r=w.hsm_start(q);check(r.has_value());
  auto modified=*r;modified.masked[0]^=1;check(!w.client_authenticate("0123456789abcdef",q,modified));
  modified=*r;modified.tag[0]^=1;check(!w.client_authenticate("0123456789abcdef",q,modified));
  modified=*r;modified.server_tag[0]^=1;check(!w.client_authenticate("0123456789abcdef",q,modified));
  modified=*r;modified.server_nonce[0]^=1;check(!w.client_authenticate("0123456789abcdef",q,modified));
  if(attested){modified=*r;modified.signature[0]^=1;check(!w.client_authenticate("0123456789abcdef",q,modified));}
  const auto proof=w.client_authenticate("0123456789abcdef",q,*r);check(proof.has_value());
  auto bad_tag=proof->tag;bad_tag[0]^=1;check(!w.hsm_finish(bad_tag));check(!w.hsm_finish(proof->tag));
  q=w.client_start("0123456789abcdef");r=w.hsm_start(q);check(r.has_value());
  check(!w.hsm_finish(proof->tag)); // old proof cannot authenticate a fresh transcript
  q=w.client_start("0123456789abcdef");r=w.hsm_start(q);check(r.has_value());const auto fresh=w.client_authenticate("0123456789abcdef",q,*r);check(fresh.has_value());
  check(fresh->tag!=proof->tag);auto ciphertext=w.hsm_finish(fresh->tag);check(ciphertext.has_value());
  auto corrupt=*ciphertext;corrupt.back()^=1;check(!w.client_finish(*fresh,corrupt));check(w.client_finish(*fresh,*ciphertext));w.validate(Stage::KeyRecovery);
  check(!w.hsm_finish(fresh->tag));
  const auto aid=w.record->aid;w.initialize();check(w.record->aid!=aid);check(w.recover("0123456789abcdef"));w.validate(Stage::KeyRecovery);
  const auto saved=*w.record;w.record->client_public=wbp::dh_keygen().pk;check(!w.recover("0123456789abcdef"));w.record=saved;
  for(int i=0;i<10;++i)check(!w.recover("incorrect"));check(w.record&&w.record->counter==0);check(!w.recover("0123456789abcdef")&&!w.record);
 }
 Config c;c.password=std::string("p\0w",3);wbp::Workload binary(c);binary.initialize();check(binary.recover(c.password));binary.validate(Stage::KeyRecovery);
 Traffic core,full;wbp::Workload a;wbp::AttestedWorkload b;a.initialize(&core);b.initialize(&full);check(full.ordinary_bytes()==core.ordinary_bytes()+128);
 std::cout<<"PASS: "<<checks<<" WBP primitive, protocol, failure, replay and accounting checks\n";return 0;
}catch(const std::exception& e){std::cerr<<"FAIL: "<<e.what()<<'\n';return 1;}}
