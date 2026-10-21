#include "protocol/sas.hpp"
#include "crypto/oprf.hpp"
#include <openssl/sha.h>
#include <algorithm>
#include <iostream>
#include <stdexcept>
using namespace ppkr;using namespace ppkr::protocol;
namespace {
int checks=0;
void check(bool yes){++checks;if(!yes)throw std::runtime_error("check "+std::to_string(checks)+" failed");}
void field(crypto::Bytes& b,std::string_view s){
  for(int i=7;i>=0;--i)b.push_back((static_cast<std::uint64_t>(s.size())>>(8*i))&255);
  b.insert(b.end(),s.begin(),s.end());
}
crypto::Key reference(const SasCommitment& first,const SasOpening& opening){
  crypto::Bytes b;std::string length(8,'\0');for(int i=0;i<8;++i)length[7-i]=(static_cast<std::uint64_t>(first.bits)>>(8*i))&255;
  field(b,"PPKR-SAS-v1/commit");field(b,length);field(b,crypto::view(first.message));
  field(b,crypto::view(opening.random.value));field(b,crypto::view(opening.salt));
  unsigned char h[64];SHA512(b.data(),b.size(),h);crypto::Key c{};std::copy_n(h,32,c.begin());return c;
}
void honest(){
  check(format_code({20,{0,0,1}})=="00001");
  check(format_code({7,{127}})=="7f");check(format_code({9,{1,255}})=="1ff");
  check(parse_code("AbCdE",20)->value==crypto::Bytes({10,188,222}));
  check(!parse_code(" abcde",20));
  for(unsigned k:{1,7,8,9,20,31,32,64,128,256})for(int i=0;i<20;++i){
    crypto::Bytes message(i==0?0:257,static_cast<unsigned char>(i));
    SasSender alice(message,{k});SasVerifier bob({k});
    check(!alice.display_code());auto first=alice.begin();check(first.message==message);
    auto challenge=bob.receive(first);check(challenge.has_value());
    auto opening=alice.open(*challenge);check(opening.has_value());
    check(first.commitment==reference(first,*opening));
    auto code=alice.display_code();check(code.has_value());
    for(std::size_t j=0;j<code->value.size();++j)check(code->value[j]==(opening->random.value[j]^challenge->random.value[j]));
    check(bob.receive(*opening));auto confirmed=bob.confirm(*code,true);check(confirmed && confirmed->matches(message));
    check(!bob.confirm(*code,true));check(!alice.open(*challenge));check(!bob.receive(*opening));
    auto text=format_code(*code);check(text.size()==(k+3)/4);
    auto decoded=parse_code(text,k);check(decoded && decoded->value==code->value);
    check(!parse_code(text+"0",k));check(!parse_code(std::string(text.size(),'g'),k));
    bool refused=false;try{alice.begin();}catch(const std::logic_error&){refused=true;}check(refused);
  }
}
void attacks(){
  for(int which=0;which<14;++which){
    SasSender alice({1,2,3});SasVerifier bob;auto first=alice.begin();
    if(which==0)first.message[0]^=1;
    if(which==1)first.commitment[0]^=1;
    if(which==2)first.bits=19;
    auto challenge=bob.receive(first);
    if(which==2){check(!challenge);continue;}check(challenge.has_value());
    if(which==3)challenge->random.value.back()^=1;
    if(which==4)challenge->random.value.pop_back();
    if(which==5)challenge->random.value[0]|=0x80;
    if(which==6)challenge->random.bits=21;
    auto opening=alice.open(*challenge);
    if(which>=4&&which<=6){check(!opening);check(!alice.display_code());continue;}
    check(opening.has_value());
    if(which==7)opening->random.value.back()^=1;
    if(which==8)opening->salt[0]^=1;
    if(which==9)opening->random.value[0]|=0x80;
    if(which==10)opening->random.value.pop_back();
    const auto valid=bob.receive(*opening);
    if(which==0||which==1||(which>=7&&which<=10)){
      check(!valid);check(!bob.confirm(*alice.display_code(),true));continue;
    }
    check(valid);auto code=*alice.display_code();
    if(which==11)code.value.back()^=1;
    if(which==12)code.value[0]|=0x80;
    check(!bob.confirm(code,which!=13)); // modified challenge/code or declined human confirmation
    check(!bob.confirm(*alice.display_code(),true));
  }
  SasSender alice({1});SasVerifier bob;auto first=alice.begin();auto challenge=*bob.receive(first);
  auto opening=*alice.open(challenge);check(bob.receive(opening));
  auto old_code=*alice.display_code();
  // An adversary-chosen fresh challenge: wrong-code rejection is deterministic,
  // while an authentic old code can coincide in a real replay with 2^-k probability.
  old_code.value.back()^=1;check(!bob.confirm(old_code,true));
  check(!parse_code("fffff",19));check(!parse_code("1ffff",16));
  for(unsigned invalid:{0,257}){bool rejected=false;try{SasVerifier v({invalid});}catch(const std::invalid_argument&){rejected=true;}check(rejected);}
  // No callback can confirm before a valid opening.
  SasVerifier fresh;check(!fresh.confirm({20,{0,0,0}},true));
}
}
int main(){try{oprf::initialize();honest();attacks();std::cout<<"PASS: "<<checks<<" SAS commitment/challenge/opening/confirmation checks\n";return 0;}
catch(const std::exception& e){std::cerr<<"FAIL: "<<e.what()<<'\n';return 1;}}
