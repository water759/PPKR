#include "evaluation/workload.hpp"
#include "evaluation/lev3.hpp"
#include <sodium.h>
#include <iomanip>
#include <iostream>
using namespace ppkr::evaluation;
int main(int argc,char** argv){try{
  ppkr::oprf::initialize();
  if(argc==2&&std::string(argv[1])=="--metadata"){
    std::cout<<"{\"build_revision\":"<<std::quoted(build_revision())
      <<",\"build_source_dirty\":"<<PPKR_BUILD_DIRTY<<",\"build_type\":"<<std::quoted(PPKR_BUILD_TYPE)
      <<",\"compiler\":"<<std::quoted(__VERSION__)<<",\"cplusplus\":"<<__cplusplus
      <<",\"libsodium\":"<<std::quoted(sodium_version_string())<<",\"sas_bits\":20}\n";return 0;
  }
  if(argc!=1)throw std::invalid_argument("usage: protocol_sizes [--metadata]");
  std::cout<<"protocol,n,t,id_bytes,password_bytes,relayed_logical_messages,relayed_payload_bytes_once,server_control_messages,server_control_bytes,direct_messages,direct_bytes,ordinary_hop_messages,ordinary_hop_bytes,sas_checks,sas_oob_bits,rendezvous_oob_bits,qr_public_key_bytes,device_record_bytes,hsm_record_bytes,guardian_records_total_bytes,guardian_record_mean_bytes,server_backup_metadata_bytes,client_output_key_bytes\n";
  auto report=[](Stage stage,Config config,auto w,const char* label){
    w.setup(stage);Traffic traffic;w.run(stage,&traffic);w.validate(stage);auto st=w.storage(stage);
    const auto n=(stage==Stage::Initialization||stage==Stage::KeyRecovery)?0:config.n;
    const auto t=n?config.t:0;
    std::cout<<label<<','<<n<<','<<t<<','<<config.id.size()<<','<<config.password.size()<<','
      <<traffic.relayed_messages<<','<<traffic.relayed_bytes<<','<<traffic.server_messages<<','<<traffic.server_bytes<<','
      <<traffic.direct_messages<<','<<traffic.direct_bytes<<','<<(2*traffic.relayed_messages+traffic.server_messages+traffic.direct_messages)<<','
      <<traffic.ordinary_bytes()<<','<<traffic.sas_checks<<','<<traffic.sas_bits<<','<<traffic.rendezvous_bits<<','<<traffic.qr_bytes<<','
      <<st.device<<','<<st.hsm<<','<<st.guardians<<','<<(n?st.guardians/n:0)<<','<<st.metadata<<','<<st.client_output<<'\n';
  };
  report(Stage::Initialization,{},Workload{},"initialization");report(Stage::KeyRecovery,{},Workload{},"key_recovery");
  report(Stage::Initialization,{},Lev3Workload{},"lev3_initialization");
  report(Stage::KeyRecovery,{},Lev3Workload{},"lev3_key_recovery");
  for(auto [n,t]:scenarios()){Config c;c.n=n;c.t=t;report(Stage::DeviceBackup,c,Workload{c},"device_backup");report(Stage::DeviceRestoration,c,Workload{c},"device_restoration");}
  return 0;
}catch(const std::exception& e){std::cerr<<"FAIL: "<<e.what()<<'\n';return 1;}}
