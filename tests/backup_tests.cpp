#include "protocol/backup.hpp"
#include <iostream>
#include <stdexcept>
#include <algorithm>
using namespace ppkr;using namespace ppkr::protocol;
namespace {
int checks=0;
void check(bool yes){++checks;if(!yes)throw std::runtime_error("check "+std::to_string(checks)+" failed");}
template<class F>void reject(F f){bool bad=false;try{f();}catch(const std::invalid_argument&){bad=true;}check(bad);}
struct Fixture {
  Device original;Hsm hsm;BackupServer server;std::vector<Guardian> guardians;Key file{};BackupMetadata metadata;
  Fixture(std::size_t t,std::size_t n):guardians(n){
    auto [p,q]=original.begin_init("alice","password");auto response=hsm.begin_init(q);
    auto upload=original.finish_init_crypto(p,response);auto initial=original.accept_init(p,hsm.accept_init("alice",upload,5),5);
    check(initial.has_value());file=*initial;
    DeviceBackup backup(original,"alice",t,n);check(!backup.complete());
    for(std::uint64_t j=1;j<=n;++j){
      auto code=server.request_code("D");check(server.rendezvous(code,"G").has_value());check(!server.rendezvous(code,"G"));
      auto init=server.relay(backup.begin_guardian(j,code));auto keys=server.relay(guardians[j-1].begin_backup(init,code,true));
      auto evidence=ideal_sas_confirm(guardians[j-1].backup_sas_message(),backup.recipient_sas_message(j,keys),true);check(evidence.has_value());
      auto ciphertext=backup.encrypt_share(j,keys,*evidence);check(ciphertext.has_value());
      auto ack=guardians[j-1].store_share(server.relay(*ciphertext));check(ack.has_value());
      auto bad=*ack;bad.signature[0]^=1;check(!backup.accept_ack(j,bad));
      if(j==n)check(!backup.complete()); // All n valid acknowledgments are required, even if t<n.
      check(backup.accept_ack(j,server.relay(*ack)));check(!backup.accept_ack(j,*ack));
    }
    auto completed=backup.complete();check(completed.has_value());metadata=*completed;server.store(metadata);
    check(!backup.complete());check(server.metadata.at("alice").coordinates.size()==n);
  }
  void restore(std::vector<std::uint64_t> subset){
    Device replacement;DeviceRestoration pending(server.metadata.at("alice"),subset);
    check(!pending.restore(replacement,20));
    for(auto j:subset){
      auto code=server.request_code("replacement");check(server.rendezvous(code,"G").has_value());
      auto request=pending.begin_guardian(j,code);auto response=guardians[j-1].begin_recovery(request,code);check(response.has_value());
      auto message=pending.recipient_sas_message(j,*response);check(message.has_value());
      auto evidence=ideal_sas_confirm(*message,*message,true);check(evidence.has_value());
      const auto count=guardians[j-1].records.size();
      auto ciphertext=guardians[j-1].release_share(pending.recipient_key(),*evidence,true,true);check(ciphertext.has_value());
      check(guardians[j-1].records.size()==count);check(pending.accept_share(j,*ciphertext));
    }
    check(pending.restore(replacement,20));check(!pending.restore(replacement,20));
    check(replacement.records.at("alice").key==original.records.at("alice").key);
    check(replacement.records.at("alice").window.counter==0&&replacement.records.at("alice").window.start==20);
    auto [r,request]=*replacement.begin_recovery("alice","password",21);
    auto response=*hsm.begin_recovery(request,21);auto auth=*replacement.authenticate(r,response);
    auto recovered=replacement.recover(r,hsm.authenticate("alice",auth));check(recovered==file);
    Client client;check(client.receive(deliver_key(*recovered,client.qr_public_key()))==file);
  }
};
void arithmetic(){
  for(auto secret:{shamir::Field{},shamir::coordinate(17),oprf::random_scalar()}){
    for(std::size_t n=1;n<=6;++n)for(std::size_t t=1;t<=n;++t){
      auto shares=shamir::split(secret,t,n);check(shares.size()==n);
      std::vector<bool> selected(n);std::fill(selected.end()-t,selected.end(),true);
      do {std::vector<shamir::Share> subset;for(std::size_t j=0;j<n;++j)if(selected[j])subset.push_back(shares[j]);
        check(shamir::reconstruct(subset)==secret);
      }while(std::next_permutation(selected.begin(),selected.end()));
    }
  }
  // Independently specified polynomial 17+3X+5X^2, no production split helper.
  std::vector<shamir::Share> known;
  for(std::uint64_t x:{1,3,5})known.push_back({shamir::coordinate(x),shamir::coordinate(17+3*x+5*x*x)});
  check(shamir::reconstruct(known)==shamir::coordinate(17));
  // Polynomial (q-1)+X wraps modulo q: points (1,0), (2,1).
  shamir::Field last{0xec,0xd3,0xf5,0x5c,0x1a,0x63,0x12,0x58,0xd6,0x9c,0xf7,0xa2,0xde,0xf9,0xde,0x14,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0x10};
  check(shamir::reconstruct({{shamir::coordinate(1),{}},{shamir::coordinate(2),shamir::coordinate(1)}})==last);
  auto q=last;++q[0];check(!shamir::canonical(q));check(shamir::canonical(last));
  auto duplicate=known;duplicate[1].x=duplicate[0].x;reject([&]{shamir::reconstruct(duplicate);});
  duplicate=known;duplicate[0].x={};reject([&]{shamir::reconstruct(duplicate);});
  duplicate=known;duplicate[0].y.fill(255);reject([&]{shamir::reconstruct(duplicate);});
  reject([&]{shamir::reconstruct({});});reject([&]{shamir::split({},0,2);});reject([&]{shamir::split({},3,2);});
}
void sas_and_binding(){
  check(!ideal_sas_confirm({1},{2},true));check(!ideal_sas_confirm({1},{1},false));
  Device device;device.records.emplace("id",DeviceRecord{oprf::random_scalar(),{0,0}});
  for(int which=0;which<5;++which){
    DeviceBackup backup(device,"id",1,1);Guardian g;auto code=crypto::random_key();auto init=backup.begin_guardian(1,code);
    if(which==0)init.version[0]^=1;
    if(which==1)init.id="different";
    auto keys=g.begin_backup(init,code,true);auto altered=keys;
    if(which==2)altered.encryption=crypto::encryption_keygen().pk;
    if(which==3)altered.acknowledgment=crypto::random_key();
    if(which==4)altered.nonce[0]^=1;
    check(!ideal_sas_confirm(g.backup_sas_message(),backup.recipient_sas_message(1,altered),true));check(!backup.complete());
  }
  Fixture f(2,3);
  for(int which=0;which<5;++which){
    DeviceRestoration r(f.metadata,{1,2});auto code=crypto::random_key();auto init=r.begin_guardian(1,code);
    auto response=*f.guardians[0].begin_recovery(init,code);auto msg=*r.recipient_sas_message(1,response);
    auto proof=*ideal_sas_confirm(msg,msg,true);auto pk=r.recipient_key();
    if(which==0)pk=crypto::encryption_keygen().pk;
    if(which==1)proof=*ideal_sas_confirm(crypto::encode({"other context"}),crypto::encode({"other context"}),true);
    auto ciphertext=f.guardians[0].release_share(pk,proof,which!=2,which!=3);
    if(which<4)check(!ciphertext);
    else {check(ciphertext.has_value());ciphertext->back()^=1;check(!r.accept_share(1,*ciphertext));}
    Device replacement;check(!r.restore(replacement,50));check(replacement.records.empty());
  }
  auto bad=f.metadata;bad.threshold=0;reject([&]{DeviceRestoration r(bad,{1,2});});
  reject([&]{DeviceRestoration r(f.metadata,{1,1});});reject([&]{DeviceRestoration r(f.metadata,{1});});
  bad=f.metadata;bad.coordinates[1]={};reject([&]{DeviceRestoration r(bad,{1,2});});
  check(!f.guardians[0].begin_recovery({"alice",crypto::random_key(),1},crypto::random_key()));
}
void recovery_boundaries(){
  Fixture f(2,3);
  for(int which=0;which<7;++which){
    DeviceRestoration r(f.metadata,{1,2});auto code=crypto::random_key();auto init=r.begin_guardian(1,code);
    auto response=*f.guardians[0].begin_recovery(init,code);
    if(which==0){++response.threshold;check(!r.recipient_sas_message(1,response));
      auto dummy=*ideal_sas_confirm({1},{1},true);check(!f.guardians[0].release_share(r.recipient_key(),dummy,true,true));continue;}
    auto msg=*r.recipient_sas_message(1,response);auto proof=*ideal_sas_confirm(msg,msg,true);
    auto ciphertext=*f.guardians[0].release_share(r.recipient_key(),proof,true,true);
    if(which==1){check(r.accept_share(1,ciphertext));check(!r.accept_share(1,ciphertext));}
    else if(which==2){check(r.accept_share(1,ciphertext));Device replacement;check(!r.restore(replacement,20));check(replacement.records.empty());}
    else if(which>=3){
      ShareContext c{init.id,init.version,response.threshold,response.count,1,response.x,code,response.nonce};
      std::string tag="RecoveryShare";auto share=shamir::coordinate(7);
      if(which==3)c.version[0]^=1;
      if(which==4)c.nonce[0]^=1;
      if(which==5)tag="BackupShare";
      if(which==6)share.fill(255);
      auto encoded=encode_context(c);auto message=crypto::encode({tag,crypto::view(encoded),crypto::view(share)});
      check(!r.accept_share(1,crypto::pke_encrypt(message,r.recipient_key())));
    }
  }
}
void malformed_shares(){
  Device device;device.records.emplace("id",DeviceRecord{oprf::random_scalar(),{0,0}});
  for(int which=0;which<4;++which){
    DeviceBackup b(device,"id",1,1);Guardian g;auto code=crypto::random_key();auto init=b.begin_guardian(1,code);auto keys=g.begin_backup(init,code,true);
    ShareContext ctx{init.id,init.version,init.threshold,init.count,init.index,init.x,code,keys.nonce};
    auto c=encode_context(ctx);auto share=shamir::coordinate(7);std::string tag="BackupShare";
    if(which==0)tag="RecoveryShare";
    if(which==1){ctx.version[0]^=1;c=encode_context(ctx);}
    if(which==2)share.fill(255);
    auto plaintext=crypto::encode({tag,crypto::view(c),crypto::view(share)});if(which==3)plaintext.push_back(0);
    auto ciphertext=crypto::pke_encrypt(plaintext,keys.encryption);check(!g.store_share(ciphertext));check(g.records.empty());
  }
}
}
int main(){try{oprf::initialize();arithmetic();
  for(auto [t,n]:{std::pair<std::size_t,std::size_t>{1,1},{1,3},{2,3},{3,5},{5,5}}){
    Fixture f(t,n);std::vector<bool> bits(n);std::fill(bits.end()-t,bits.end(),true);
    do{std::vector<std::uint64_t> indices;for(std::size_t j=0;j<n;++j)if(bits[j])indices.push_back(j+1);f.restore(indices);}
    while(std::next_permutation(bits.begin(),bits.end()));
  }
  sas_and_binding();recovery_boundaries();malformed_shares();std::cout<<"PASS: "<<checks<<" Shamir/backup/restoration/lifecycle checks\n";return 0;
}catch(const std::exception& e){std::cerr<<"FAIL: "<<e.what()<<'\n';return 1;}}
