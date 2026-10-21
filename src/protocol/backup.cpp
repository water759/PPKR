#include "protocol/backup.hpp"
#include <sodium.h>
#include <stdexcept>
#include <algorithm>
namespace ppkr::protocol {
namespace {
std::string number(std::uint64_t n){std::string b(8,'\0');for(int i=0;i<8;++i)b[7-i]=(n>>(8*i))&255;return b;}
void validate(const BackupInit& p){
  if(!p.threshold||p.threshold>p.count||!p.index||p.index>p.count||p.x!=shamir::coordinate(p.index))
    throw std::invalid_argument("invalid backup parameters");
}
ShareContext context(const BackupInit& p,const Key& code,const Key& nonce){
  return {p.id,p.version,p.threshold,p.count,p.index,p.x,code,nonce};
}
Bytes share_message(std::string_view tag,const ShareContext& c,const Scalar& share){
  const auto ctx=encode_context(c);return crypto::encode({tag,crypto::view(ctx),crypto::view(share)});
}
std::optional<Scalar> parse_share(const Bytes& m,std::string_view tag,const ShareContext& c){
  const auto ctx=encode_context(c);const auto prefix=crypto::encode({tag,crypto::view(ctx)});
  if(m.size()!=prefix.size()+40||!std::equal(prefix.begin(),prefix.end(),m.begin()))return std::nullopt;
  const auto pos=prefix.size();for(int i=0;i<7;++i)if(m[pos+i]!=0)return std::nullopt;
  if(m[pos+7]!=32)return std::nullopt;
  Scalar y{};std::copy_n(m.begin()+pos+8,32,y.begin());if(!shamir::canonical(y))return std::nullopt;return y;
}
Bytes backup_sas(const ShareContext& c,const GuardianKeys& keys){
  auto ctx=encode_context(c);return crypto::encode({"ShareRecipient",crypto::view(ctx),crypto::view(keys.encryption),crypto::view(keys.acknowledgment)});
}
Bytes recovery_sas(const ShareContext& c,const Key& recipient){
  auto ctx=encode_context(c);return crypto::encode({"RecoveryRecipient",crypto::view(ctx),crypto::view(recipient)});
}
Bytes ack_message(const ShareContext& c,const Bytes& ciphertext){
  auto ctx=encode_context(c);return crypto::encode({"ShareStored",crypto::view(ctx),crypto::view(ciphertext)});
}
void wipe(Bytes& b){if(!b.empty())sodium_memzero(b.data(),b.size());}
}
Bytes encode_context(const ShareContext& c){
  return crypto::encode({c.id,crypto::view(c.version),number(c.threshold),number(c.count),number(c.index),crypto::view(c.x),crypto::view(c.code),crypto::view(c.nonce)});
}
Key BackupServer::request_code(std::string connection){
  auto code=crypto::random_key();while(codes.count(code))code=crypto::random_key();codes.emplace(code,std::move(connection));return code;
}
std::optional<std::pair<std::string,std::string>> BackupServer::rendezvous(const Key& code,std::string guardian){
  auto it=codes.find(code);if(it==codes.end())return std::nullopt;
  auto result=std::make_pair(it->second,std::move(guardian));codes.erase(it);return result;
}
Guardian::PendingBackup::~PendingBackup(){
  sodium_memzero(encryption.sk.data(),encryption.sk.size());sodium_memzero(acknowledgment.sk.data(),acknowledgment.sk.size());
}
GuardianKeys Guardian::begin_backup(const BackupInit& init,const Key& code,bool agrees){
  validate(init);if(!agrees||backup)throw std::invalid_argument("guardian declined or busy");
  auto enc=crypto::encryption_keygen();auto seed=crypto::random_key();auto ack=crypto::signing_from_seed(seed);
  auto nonce=crypto::random_key();backup.emplace(PendingBackup{context(init,code,nonce),enc,ack});
  sodium_memzero(seed.data(),seed.size());sodium_memzero(enc.sk.data(),enc.sk.size());sodium_memzero(ack.sk.data(),ack.sk.size());
  return {backup->encryption.pk,backup->acknowledgment.pk,nonce};
}
Bytes Guardian::backup_sas_message()const{
  if(!backup)throw std::invalid_argument("no pending backup");
  return backup_sas(backup->context,{backup->encryption.pk,backup->acknowledgment.pk,backup->context.nonce});
}
std::optional<BackupAck> Guardian::store_share(const Bytes& ciphertext){
  if(!backup)return std::nullopt;
  auto pending=*backup;backup.reset();auto plaintext=crypto::pke_decrypt(ciphertext,pending.encryption);
  if(!plaintext)return std::nullopt;
  auto share=parse_share(*plaintext,"BackupShare",pending.context);wipe(*plaintext);if(!share)return std::nullopt;
  const auto& c=pending.context;BackupInit parameters{c.id,c.version,c.threshold,c.count,c.index,c.x};
  records.push_back({parameters,shamir::Share{c.x,*share}});sodium_memzero(share->data(),share->size());
  return BackupAck{crypto::sign(ack_message(c,ciphertext),pending.acknowledgment)};
}
DeviceBackup::DeviceBackup(const Device& d,const std::string& id,std::size_t t,std::size_t n){
  auto it=d.records.find(id);if(it==d.records.end())throw std::invalid_argument("missing device record");
  metadata={id,crypto::random_key(),t,n,{}};shares=shamir::split(it->second.key,t,n);
  for(std::size_t j=1;j<=n;++j)metadata.coordinates.emplace(j,shamir::coordinate(j));
}
BackupInit DeviceBackup::begin_guardian(std::uint64_t j,const Key& code){
  if(terminal||!metadata.coordinates.count(j)||deliveries.count(j))throw std::invalid_argument("invalid backup step");
  BackupInit p{metadata.id,metadata.version,metadata.threshold,metadata.count,j,metadata.coordinates.at(j)};
  deliveries.emplace(j,Delivery{context(p,code,{}),std::nullopt,std::nullopt,false});return p;
}
Bytes DeviceBackup::recipient_sas_message(std::uint64_t j,const GuardianKeys& keys)const{
  if(terminal)throw std::invalid_argument("backup terminated");
  auto c=deliveries.at(j).context;c.nonce=keys.nonce;return backup_sas(c,keys);
}
std::optional<Bytes> DeviceBackup::encrypt_share(std::uint64_t j,const GuardianKeys& keys,const AuthenticatedMessage& sas){
  if(terminal)return std::nullopt;
  auto& delivery=deliveries.at(j);
  if(delivery.ciphertext)return std::nullopt;
  if(!sas.matches(recipient_sas_message(j,keys))){terminal=true;shares.clear();return std::nullopt;}
  delivery.context.nonce=keys.nonce;delivery.keys=keys;
  auto plaintext=share_message("BackupShare",delivery.context,shares.at(j-1).y);
  auto ciphertext=crypto::pke_encrypt(plaintext,keys.encryption);wipe(plaintext);
  delivery.ciphertext=ciphertext;return ciphertext;
}
bool DeviceBackup::accept_ack(std::uint64_t j,const BackupAck& ack){
  if(terminal)return false;
  auto& d=deliveries.at(j);
  if(!d.keys||!d.ciphertext||d.acknowledged)return false;
  if(!crypto::verify(ack_message(d.context,*d.ciphertext),ack.signature,d.keys->acknowledgment))return false;
  d.acknowledged=true;return true;
}
std::optional<BackupMetadata> DeviceBackup::complete(){
  if(terminal||deliveries.size()!=metadata.count)return std::nullopt;
  for(const auto& [j,d]:deliveries)if(!d.acknowledged)return std::nullopt;
  terminal=true;shares.clear();deliveries.clear();return metadata;
}
std::optional<GuardianRecResponse> Guardian::begin_recovery(const DevRecInit& init,const Key& code){
  if(recovery)throw std::invalid_argument("recovery active");
  for(const auto& record:records){const auto& p=record.parameters;
    if(p.id==init.id&&p.version==init.version&&p.index==init.index){
      recovery=context(p,code,crypto::random_key());return GuardianRecResponse{p.threshold,p.count,p.x,recovery->nonce};
    }
  }
  return std::nullopt;
}
std::optional<Bytes> Guardian::release_share(const Key& recipient,const AuthenticatedMessage& sas,bool owner,bool approves){
  if(!recovery)return std::nullopt;
  auto c=*recovery;recovery.reset();
  if(!owner||!approves||!sas.matches(recovery_sas(c,recipient)))return std::nullopt;
  for(const auto& r:records)if(r.parameters.id==c.id&&r.parameters.version==c.version&&r.parameters.index==c.index){
    auto plaintext=share_message("RecoveryShare",c,r.share.y);auto result=crypto::pke_encrypt(plaintext,recipient);wipe(plaintext);return result;
  }
  return std::nullopt;
}
DeviceRestoration::DeviceRestoration(BackupMetadata m,std::vector<std::uint64_t> indices):metadata(std::move(m)){
  if(!metadata.threshold||metadata.threshold>metadata.count||metadata.coordinates.size()!=metadata.count||indices.size()!=metadata.threshold)
    throw std::invalid_argument("invalid recovery metadata/subset");
  for(const auto& [j,x]:metadata.coordinates)if(!j||j>metadata.count||x!=shamir::coordinate(j))throw std::invalid_argument("invalid metadata coordinate");
  for(auto j:indices)if(!metadata.coordinates.count(j)||!selected.insert(j).second)throw std::invalid_argument("invalid recovery subset");
  encryption=crypto::encryption_keygen();
}
void DeviceRestoration::erase(){shares.clear();contexts.clear();prepared.clear();sodium_memzero(encryption.sk.data(),encryption.sk.size());terminal=true;}
DeviceRestoration::~DeviceRestoration(){erase();}
DevRecInit DeviceRestoration::begin_guardian(std::uint64_t j,const Key& code){
  if(terminal||!selected.count(j)||contexts.count(j))throw std::invalid_argument("invalid restoration step");
  contexts.emplace(j,ShareContext{metadata.id,metadata.version,metadata.threshold,metadata.count,j,metadata.coordinates.at(j),code,{}});
  return {metadata.id,metadata.version,j};
}
std::optional<Bytes> DeviceRestoration::recipient_sas_message(std::uint64_t j,const GuardianRecResponse& r){
  if(terminal||prepared.count(j))return std::nullopt;
  auto& c=contexts.at(j);
  if(r.threshold!=c.threshold||r.count!=c.count||r.x!=c.x){erase();return std::nullopt;}
  c.nonce=r.nonce;prepared.insert(j);return recovery_sas(c,encryption.pk);
}
bool DeviceRestoration::accept_share(std::uint64_t j,const Bytes& ciphertext){
  if(terminal||!contexts.count(j)||!prepared.count(j))return false;
  const auto& c=contexts.at(j);
  for(const auto& share:shares)if(share.x==c.x){erase();return false;}
  auto plaintext=crypto::pke_decrypt(ciphertext,encryption);if(!plaintext){erase();return false;}
  auto share=parse_share(*plaintext,"RecoveryShare",c);wipe(*plaintext);if(!share){erase();return false;}
  shares.push_back(shamir::Share{c.x,*share});sodium_memzero(share->data(),share->size());return true;
}
bool DeviceRestoration::restore(Device& replacement,Time now){
  if(terminal||shares.size()!=metadata.threshold||replacement.records.count(metadata.id))return false;
  auto secret=shamir::reconstruct(shares);replacement.records.emplace(metadata.id,DeviceRecord{secret,{0,now}});
  sodium_memzero(secret.data(),secret.size());erase();return true;
}
}
