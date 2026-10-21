#include "evaluation/workload.hpp"
#include <stdexcept>
namespace ppkr::evaluation {
using namespace protocol;using crypto::Bytes;using crypto::view;
namespace {
void require(bool b){if(!b)throw std::runtime_error("evaluation workload correctness failure");}
std::string number(std::uint64_t n){std::string s(8,'\0');for(int i=0;i<8;++i)s[7-i]=(n>>(8*i))&255;return s;}
Bytes metadata_bytes(const BackupMetadata& m){
  Bytes coords;for(const auto& [j,x]:m.coordinates){auto pair=crypto::encode({number(j),view(x)});coords.insert(coords.end(),pair.begin(),pair.end());}
  return crypto::encode({"BackupRecord",m.id,view(m.version),number(m.threshold),number(m.count),view(coords)});
}
}
const char* name(Stage s){switch(s){case Stage::Initialization:return "initialization";case Stage::KeyRecovery:return "key_recovery";case Stage::DeviceBackup:return "device_backup";case Stage::DeviceRestoration:return "device_restoration";}throw std::invalid_argument("unknown stage");}
std::string build_revision(){return PPKR_BUILD_REVISION;}
std::vector<std::pair<std::size_t,std::size_t>> scenarios(){return {{1,1},{3,1},{3,2},{3,3},{5,1},{5,3},{5,5},{10,1},{10,6},{10,10},{20,1},{20,11},{20,20}};}
Workload::Workload(Config c):config(std::move(c)),guardians(config.n){if(!config.t||config.t>config.n)throw std::invalid_argument("invalid evaluation configuration");}
void Workload::relayed(const Bytes& m){if(traffic){traffic->relayed_bytes+=m.size();++traffic->relayed_messages;}}
void Workload::control(const Bytes& m){if(traffic){traffic->server_bytes+=m.size();++traffic->server_messages;}}
crypto::Key Workload::rendezvous(){
  if(traffic)control(crypto::encode({"RequestCode"}));
  auto code=server.request_code("device");
  if(traffic){control(crypto::encode({"RendezvousCode",view(code)}));control(crypto::encode({"JoinCode",view(code)}));traffic->rendezvous_bits+=256;}
  require(server.rendezvous(code,"guardian").has_value());return code;
}
AuthenticatedMessage Workload::sas(const Bytes& message,const Bytes& expected){
  SasSender sender(message);SasVerifier verifier;
  auto first=sender.begin();if(traffic)relayed(crypto::encode({"SASCommit",number(first.bits),view(first.message),view(first.commitment)}));
  auto challenge=verifier.receive(first);require(challenge.has_value());
  if(traffic)relayed(crypto::encode({"SASChallenge",view(challenge->random.value)}));
  auto opening=sender.open(*challenge);require(opening.has_value());
  if(traffic)relayed(crypto::encode({"SASOpen",view(opening->random.value),view(opening->salt)}));
  require(verifier.receive(*opening));auto code=sender.display_code();require(code.has_value());
  // Only human/OOB transfer is simulated; no hash/proof steps are skipped.
  auto evidence=verifier.confirm(*code,true);require(evidence.has_value()&&evidence->matches(expected));
  if(traffic){traffic->sas_bits+=code->bits;++traffic->sas_checks;}return *evidence;
}
void Workload::initialize(){
  auto [p,q]=device.begin_init(config.id,config.password);
  if(traffic)relayed(crypto::encode({"Init",view(q.a),q.id}));
  auto response=server.relay(hsm.begin_init(server.relay(q)));
  if(traffic)relayed(crypto::encode({"InitReply",view(response.b),view(response.pk_enc),response.id}));
  auto upload=device.finish_init_crypto(p,response);
  if(traffic)relayed(crypto::encode({"InitUpload",view(upload.ciphertext)}));
  auto result=server.relay(hsm.accept_init(config.id,server.relay(upload),0));
  if(traffic)relayed(crypto::encode({"InitRes",std::string_view(result.success?"\1":"\0",1)}));
  original=device.accept_init(p,result,0);require(original.has_value());
}
void Workload::recover(){
  auto start=device.begin_recovery(config.id,config.password,1);require(start.has_value());auto [p,q]=std::move(*start);
  if(traffic)relayed(crypto::encode({"Rec",view(q.a),q.id}));
  auto response=hsm.begin_recovery(server.relay(q),1);require(response.has_value());
  if(traffic)relayed(crypto::encode({"RecReply",view(response->b),view(response->cmk),view(response->nonce),response->id}));
  auto auth=device.authenticate(p,server.relay(*response));require(auth.has_value());
  if(traffic)relayed(crypto::encode({"RecAuth",view(auth->signature)}));
  auto result=server.relay(hsm.authenticate(config.id,server.relay(*auth)));require(result.success&&result.ciphertext.has_value());
  if(traffic)relayed(crypto::encode({"RecRes",std::string_view("\1",1),view(*result.ciphertext)}));
  recovered=device.recover(p,result);require(recovered.has_value());Client client;
  const auto pk=client.qr_public_key();if(traffic)traffic->qr_bytes+=pk.size();
  auto delivery=deliver_key(*recovered,pk);
  if(traffic){auto bytes=crypto::encode({"KeyDelivery",view(delivery)});traffic->direct_bytes+=bytes.size();++traffic->direct_messages;}
  client_key=client.receive(delivery);require(client_key.has_value());
}
void Workload::backup(){
  DeviceBackup pending(device,config.id,config.t,config.n);
  for(std::uint64_t j=1;j<=config.n;++j){
    auto code=rendezvous();auto init=pending.begin_guardian(j,code);
    if(traffic)relayed(crypto::encode({"BackupInit",init.id,view(init.version),number(init.threshold),number(init.count),number(init.index),view(init.x)}));
    auto keys=server.relay(guardians[j-1].begin_backup(server.relay(init),code,true));
    if(traffic)relayed(crypto::encode({"GuardianKeys",view(keys.encryption),view(keys.acknowledgment),view(keys.nonce)}));
    auto evidence=sas(guardians[j-1].backup_sas_message(),pending.recipient_sas_message(j,keys));
    auto ciphertext=pending.encrypt_share(j,keys,evidence);require(ciphertext.has_value());
    if(traffic)relayed(crypto::encode({"BackupCiphertext",view(*ciphertext)}));
    auto ack=guardians[j-1].store_share(server.relay(*ciphertext));require(ack.has_value());
    if(traffic)relayed(crypto::encode({"BackupAck",view(ack->signature)}));
    require(pending.accept_ack(j,server.relay(*ack)));
  }
  backup_metadata=pending.complete();require(backup_metadata.has_value());
  if(traffic)control(metadata_bytes(*backup_metadata));
  server.store(*backup_metadata);
}
void Workload::restore(){
  if(traffic)control(crypto::encode({"GetBackup",config.id}));
  const auto metadata=server.metadata.at(config.id);if(traffic)control(metadata_bytes(metadata));
  std::vector<std::uint64_t> selected;for(std::size_t j=1;j<=config.t;++j)selected.push_back(j);
  DeviceRestoration pending(metadata,selected);
  for(auto j:selected){
    auto code=rendezvous();auto init=pending.begin_guardian(j,code);
    if(traffic)relayed(crypto::encode({"DevRecInit",init.id,view(init.version),number(init.index)}));
    auto response=guardians[j-1].begin_recovery(server.relay(init),code);require(response.has_value());
    if(traffic)relayed(crypto::encode({"GuardianRecReply",number(response->threshold),number(response->count),view(response->x),view(response->nonce)}));
    auto message=pending.recipient_sas_message(j,server.relay(*response));require(message.has_value());
    auto evidence=sas(*message,*message);
    auto ciphertext=guardians[j-1].release_share(pending.recipient_key(),evidence,true,true);require(ciphertext.has_value());
    if(traffic)relayed(crypto::encode({"RecoveryCiphertext",view(*ciphertext)}));
    require(pending.accept_share(j,server.relay(*ciphertext)));
  }
  require(pending.restore(restored,2));
}
void Workload::setup(Stage s){if(s!=Stage::Initialization)initialize();if(s==Stage::DeviceRestoration)backup();}
void Workload::run(Stage s,Traffic* accounting){
  traffic=accounting;
  try{switch(s){case Stage::Initialization:initialize();break;case Stage::KeyRecovery:recover();break;case Stage::DeviceBackup:backup();break;case Stage::DeviceRestoration:restore();break;}}
  catch(...){traffic=nullptr;throw;}traffic=nullptr;
}
void Workload::validate(Stage s)const{
  require(original.has_value());require(device.records.count(config.id)&&hsm.records.count(config.id));
  if(s==Stage::KeyRecovery)require(recovered==original&&client_key==original);
  if(s==Stage::DeviceBackup){require(backup_metadata.has_value());std::vector<shamir::Share> shares;
    for(std::size_t j=0;j<config.t;++j){require(guardians[j].records.size()==1);shares.push_back(guardians[j].records[0].share);}
    require(shamir::reconstruct(shares)==device.records.at(config.id).key);
  }
  if(s==Stage::DeviceRestoration)require(restored.records.at(config.id).key==device.records.at(config.id).key);
}
Storage Workload::storage(Stage s)const{
  Storage out;const auto& record=(s==Stage::DeviceRestoration?restored:device).records.at(config.id);
  out.device=crypto::encode({"DeviceRecord",config.id,view(record.key),number(record.window.counter),number(record.window.start)}).size();
  const auto& h=hsm.records.at(config.id);
  out.hsm=crypto::encode({"HSMRecord",config.id,view(h.cmk),view(h.cf),view(h.pk_c),view(h.key),number(h.window.counter),number(h.window.start)}).size();
  if(backup_metadata){out.metadata=metadata_bytes(*backup_metadata).size();
    for(const auto& g:guardians)for(const auto& r:g.records){const auto& p=r.parameters;
      out.guardians+=crypto::encode({"GuardianRecord",p.id,view(p.version),number(p.threshold),number(p.count),number(p.index),view(p.x),view(r.share.y)}).size();}
  }
  out.client_output=client_key?32:0;return out;
}
}
