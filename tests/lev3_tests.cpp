#include "evaluation/lev3.hpp"
#include <iostream>
#include <stdexcept>
using namespace ppkr::evaluation;
int main(){try{
  ppkr::oprf::initialize();int checks=0;
  auto check=[&](bool b){++checks;if(!b)throw std::runtime_error("Level-3 check "+std::to_string(checks));};
  for(auto stage:{Stage::Initialization,Stage::KeyRecovery}){
    Lev3Workload w;w.setup(stage);Traffic t;w.run(stage,&t);w.validate(stage);
    check(t.relayed_messages==3&&t.server_messages==1);
    check(t.direct_messages==0&&t.sas_checks==0&&t.qr_bytes==0);
    const auto st=w.storage(stage);check(st.device==0&&st.guardians==0&&st.hsm>128);
    Lev3Workload other;other.setup(stage);Traffic t2;other.run(stage,&t2);other.validate(stage);
    check(t.ordinary_bytes()==t2.ordinary_bytes());
  }
  Lev3Workload w;w.initialize();
  check(!w.recover("incorrect"));check(w.record->counter==9);
  check(w.recover("0123456789abcdef"));check(w.record->counter==10);w.validate(Stage::KeyRecovery);
  const auto saved=*w.record;
  w.record->ciphertext[0]^=1;check(!w.recover("0123456789abcdef"));
  w.record=saved;w.record->pk=ppkr::crypto::signing_from_seed(ppkr::crypto::random_key()).pk;
  check(!w.recover("0123456789abcdef")); // correct decryption cannot bypass signature authentication
  w.record=saved;w.record->oprf_key=ppkr::oprf::random_scalar();
  check(!w.recover("0123456789abcdef"));
  w.record=saved;
  for(int i=0;i<10;++i)check(!w.recover("incorrect"));
  check(w.record.has_value()&&w.record->counter==0);
  check(!w.recover("0123456789abcdef")&&!w.record.has_value());
  check(!w.recover("0123456789abcdef"));
  Config c;c.id="bob@example.org";c.password=std::string("a\0b",3);
  Lev3Workload binary(c);binary.initialize();check(binary.recover(c.password));binary.validate(Stage::KeyRecovery);
  std::cout<<"PASS: "<<checks<<" Level-3 correctness/accounting checks\n";return 0;
}catch(const std::exception& e){std::cerr<<"FAIL: "<<e.what()<<'\n';return 1;}}
