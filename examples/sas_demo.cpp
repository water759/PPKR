#include "protocol/sas.hpp"
#include "crypto/oprf.hpp"
#include <iostream>
#include <stdexcept>
int main(int argc,char** argv){
  using namespace ppkr;using namespace ppkr::protocol;
  try{
    oprf::initialize();
    const bool simulate=argc==2&&std::string(argv[1])=="--auto-confirm-for-test";
    if(argc>1&&!simulate)throw std::invalid_argument("usage: sas_demo [--auto-confirm-for-test]");
    const auto payload=crypto::encode({"SAS demo","public message to authenticate"});
    SasSender alice(payload);SasVerifier bob;
    auto commitment=alice.begin();auto challenge=bob.receive(commitment);
    if(!challenge)throw std::runtime_error("commitment rejected");
    auto opening=alice.open(*challenge);
    if(!opening||!bob.receive(*opening))throw std::runtime_error("opening rejected");
    const auto sender_code=*alice.display_code();
    std::cout<<"Alice displays: "<<format_code(sender_code)<<" (20 bits, hexadecimal)\n";
    std::optional<ShortCode> code;bool confirms=false;
    if(simulate){
      std::cout<<"TEST MODE: authenticated OOB delivery and human confirmation are simulated.\n";
      code=sender_code;confirms=true;
    }else{
      std::cout<<"Single-process demonstration. Real peer identity/OOB transport is not implemented.\n"
        <<"Bob: enter Alice's code obtained through the authenticated OOB channel: "<<std::flush;
      std::string text;if(!std::getline(std::cin,text))return 1;code=parse_code(text,20);
      std::cout<<"Confirm the sender's identity and OOB code delivery? Type yes: "<<std::flush;
      std::string answer;if(!std::getline(std::cin,answer))return 1;confirms=answer=="yes";
    }
    if(!code){std::cerr<<"REJECT: invalid code encoding\n";return 1;}
    auto result=bob.confirm(*code,confirms);
    if(!result||!result->matches(payload)){std::cerr<<"REJECT: SAS verification failed\n";return 1;}
    std::cout<<"PASS: message authenticated by SAS verifier\n";return 0;
  }catch(const std::exception& e){std::cerr<<"FAIL: "<<e.what()<<'\n';return 1;}
}
