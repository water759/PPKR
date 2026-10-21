#include "protocol/backup.hpp"
#include <iostream>
#include <stdexcept>
using namespace ppkr;using namespace ppkr::protocol;
namespace {
// Automated harness: only delivery of the sender's authenticated short code and
// the user's approval are simulated; all three insecure-channel moves execute.
std::optional<AuthenticatedMessage> run_sas(const crypto::Bytes& sender_message,
    const crypto::Bytes& expected_message,bool user_confirms) {
  SasSender sender(sender_message); SasVerifier verifier;
  auto first=sender.begin(); auto challenge=verifier.receive(first);
  if(!challenge) return std::nullopt;
  auto opening=sender.open(*challenge);
  if(!opening || !verifier.receive(*opening)) return std::nullopt;
  auto authenticated_code=sender.display_code();
  if(!authenticated_code) return std::nullopt;
  auto evidence=verifier.confirm(*authenticated_code,user_confirms);
  if(!evidence || !evidence->matches(expected_message)) return std::nullopt;
  return evidence;
}
void require(bool value){if(!value)throw std::runtime_error("lifecycle step failed");}}
int main(){try{
  oprf::initialize();Device original;Hsm hsm;BackupServer server;std::vector<Guardian> guardians(5);
  auto [p,q]=original.begin_init("demo-user","demo-password");
  auto response=hsm.begin_init(server.relay(q));auto upload=original.finish_init_crypto(p,response);
  auto file=original.accept_init(p,hsm.accept_init("demo-user",upload,0),0);require(file.has_value());
  DeviceBackup backup(original,"demo-user",3,5);
  for(std::uint64_t j=1;j<=5;++j){
    auto code=server.request_code("original-device");require(server.rendezvous(code,"guardian").has_value());
    auto init=backup.begin_guardian(j,code);auto keys=guardians[j-1].begin_backup(init,code,true);
    auto sas=run_sas(guardians[j-1].backup_sas_message(),backup.recipient_sas_message(j,keys),true);require(sas.has_value());
    auto ciphertext=backup.encrypt_share(j,keys,*sas);require(ciphertext.has_value());
    auto ack=guardians[j-1].store_share(*ciphertext);require(ack.has_value());require(backup.accept_ack(j,*ack));
  }
  auto metadata=backup.complete();require(metadata.has_value());server.store(*metadata);
  Device replacement;DeviceRestoration restoration(server.metadata.at("demo-user"),{1,3,5});
  for(std::uint64_t j:{1,3,5}){
    auto code=server.request_code("replacement-device");require(server.rendezvous(code,"guardian").has_value());
    auto init=restoration.begin_guardian(j,code);auto reply=guardians[j-1].begin_recovery(init,code);require(reply.has_value());
    auto msg=restoration.recipient_sas_message(j,*reply);require(msg.has_value());
    // Guardian::release_share additionally checks its own application context.
    auto sas=run_sas(*msg,*msg,true);require(sas.has_value());
    auto ciphertext=guardians[j-1].release_share(restoration.recipient_key(),*sas,true,true);require(ciphertext.has_value());
    require(restoration.accept_share(j,*ciphertext));
  }
  require(restoration.restore(replacement,100));
  require(replacement.records.at("demo-user").key==original.records.at("demo-user").key);
  auto begin=replacement.begin_recovery("demo-user","demo-password",101);require(begin.has_value());
  auto [r,request]=std::move(*begin);auto reply=hsm.begin_recovery(request,101);require(reply.has_value());
  auto auth=replacement.authenticate(r,*reply);require(auth.has_value());
  auto recovered=replacement.recover(r,hsm.authenticate("demo-user",*auth));require(recovered==file);
  Client client;require(client.receive(deliver_key(*recovered,client.qr_public_key()))==file);
  std::cout<<"Initialization: PASS\n3-of-5 guardian backup: PASS\nDevice restoration from guardians 1,3,5: PASS\nRecovered device secret matches original: PASS\nKey recovery and client delivery: PASS\nSAS-MA: Vaudenay 2005 Figure 5; human OOB transfer simulated\n";
  return 0;
}catch(const std::exception& e){std::cerr<<"FAIL: "<<e.what()<<'\n';return 1;}}
