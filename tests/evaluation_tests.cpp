#include "evaluation/workload.hpp"
#include <iostream>
#include <stdexcept>
using namespace ppkr::evaluation;
int main(){try{
  ppkr::oprf::initialize();int checks=0;
  auto check=[&](bool b){++checks;if(!b)throw std::runtime_error("evaluation check "+std::to_string(checks)+" failed");};
  for(auto stage:{Stage::Initialization,Stage::KeyRecovery,Stage::DeviceBackup,Stage::DeviceRestoration}){
    Workload w;w.setup(stage);Traffic m;w.run(stage,&m);w.validate(stage);const auto st=w.storage(stage);
    check(st.device>32&&st.hsm>64);check(m.ordinary_bytes()==2*m.relayed_bytes+m.server_bytes+m.direct_bytes);
    if(stage==Stage::Initialization){check(m.relayed_messages==4);check(m.server_messages==0);check(m.sas_checks==0);check(st.guardians==0);}
    if(stage==Stage::KeyRecovery){check(m.relayed_messages==4);check(m.direct_messages==1);check(m.qr_bytes==32);check(st.client_output==32);}
    if(stage==Stage::DeviceBackup){check(m.relayed_messages==7*5);check(m.server_messages==3*5+1);check(m.sas_bits==20*5);check(m.rendezvous_bits==256*5);}
    if(stage==Stage::DeviceRestoration){check(m.relayed_messages==6*3);check(m.server_messages==2+3*3);check(m.sas_bits==20*3);check(m.rendezvous_bits==256*3);}
    Workload again;again.setup(stage);Traffic repeated;again.run(stage,&repeated);again.validate(stage);
    check(repeated.ordinary_bytes()==m.ordinary_bytes()); // Random coins do not alter lengths.
  }
  for(auto [n,t]:scenarios())for(auto stage:{Stage::DeviceBackup,Stage::DeviceRestoration}){
    Config c;c.n=n;c.t=t;Workload w(c);w.setup(stage);Traffic m;w.run(stage,&m);w.validate(stage);
    check(m.sas_checks==(stage==Stage::DeviceBackup?n:t));check(w.storage(stage).guardians%n==0);
  }
  std::cout<<"PASS: "<<checks<<" evaluation workload/accounting checks\n";return 0;
}catch(const std::exception& e){std::cerr<<"FAIL: "<<e.what()<<'\n';return 1;}}
