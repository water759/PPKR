#pragma once
#include "protocol/core.hpp"
#include "crypto/shamir.hpp"
#include <set>
namespace ppkr::protocol {
// Ideal SAS-MA functionality for correctness simulation, not a short-code protocol.
class AuthenticatedMessage {
  Bytes value;
  explicit AuthenticatedMessage(Bytes bytes):value(std::move(bytes)){}
  friend std::optional<AuthenticatedMessage> ideal_sas_confirm(const Bytes&,const Bytes&,bool);
public:
  bool matches(const Bytes& bytes)const{return value==bytes;}
};
std::optional<AuthenticatedMessage> ideal_sas_confirm(const Bytes& sender,const Bytes& verifier,bool user_confirms);
struct BackupMetadata {
  std::string id; Key version; std::size_t threshold,count;
  std::map<std::uint64_t,Scalar> coordinates;
};
struct ShareContext {
  std::string id; Key version; std::size_t threshold,count; std::uint64_t index; Scalar x; Key code,nonce;
};
Bytes encode_context(const ShareContext& context);
struct BackupInit {std::string id;Key version;std::size_t threshold,count;std::uint64_t index;Scalar x;};
struct GuardianKeys {Key encryption,acknowledgment,nonce;};
struct BackupAck {crypto::Signature signature;};
struct DevRecInit {std::string id;Key version;std::uint64_t index;};
struct GuardianRecResponse {std::size_t threshold,count;Scalar x;Key nonce;};
struct GuardianRecord {BackupInit parameters;shamir::Share share;};
struct BackupServer:Server {
  std::map<std::string,BackupMetadata> metadata;
  Key request_code(std::string device_connection);
  std::optional<std::pair<std::string,std::string>> rendezvous(const Key& code,std::string guardian_connection);
  void store(const BackupMetadata& record){metadata.insert_or_assign(record.id,record);}
private:
  std::map<Key,std::string> codes;
};
class Guardian {
  struct PendingBackup {
    ShareContext context; crypto::EncryptionKeys encryption; crypto::SigningKeys acknowledgment;
    ~PendingBackup();
  };
  std::optional<PendingBackup> backup;
  std::optional<ShareContext> recovery;
public:
  std::vector<GuardianRecord> records;
  GuardianKeys begin_backup(const BackupInit& init,const Key& submitted_code,bool agrees);
  Bytes backup_sas_message()const;
  std::optional<BackupAck> store_share(const Bytes& ciphertext);
  std::optional<GuardianRecResponse> begin_recovery(const DevRecInit& init,const Key& submitted_code);
  std::optional<Bytes> release_share(const Key& recipient,const AuthenticatedMessage& sas,bool recognizes_owner,bool approves);
};
class DeviceBackup {
  BackupMetadata metadata;
  std::vector<shamir::Share> shares;
  struct Delivery {ShareContext context;std::optional<GuardianKeys> keys;std::optional<Bytes> ciphertext;bool acknowledged=false;};
  std::map<std::uint64_t,Delivery> deliveries;
  bool terminal=false;
public:
  DeviceBackup(const Device& device,const std::string& id,std::size_t threshold,std::size_t count);
  BackupInit begin_guardian(std::uint64_t index,const Key& code);
  Bytes recipient_sas_message(std::uint64_t index,const GuardianKeys& keys)const;
  std::optional<Bytes> encrypt_share(std::uint64_t index,const GuardianKeys& keys,const AuthenticatedMessage& sas);
  bool accept_ack(std::uint64_t index,const BackupAck& ack);
  std::optional<BackupMetadata> complete();
};
class DeviceRestoration {
  BackupMetadata metadata;
  std::set<std::uint64_t> selected,prepared;
  crypto::EncryptionKeys encryption;
  std::map<std::uint64_t,ShareContext> contexts;
  std::vector<shamir::Share> shares;
  bool terminal=false;
  void erase();
public:
  DeviceRestoration(BackupMetadata metadata,std::vector<std::uint64_t> indices);
  ~DeviceRestoration();
  DeviceRestoration(const DeviceRestoration&)=delete;
  DeviceRestoration& operator=(const DeviceRestoration&)=delete;
  DevRecInit begin_guardian(std::uint64_t index,const Key& code);
  std::optional<Bytes> recipient_sas_message(std::uint64_t index,const GuardianRecResponse& reply);
  Key recipient_key()const{return encryption.pk;}
  bool accept_share(std::uint64_t index,const Bytes& ciphertext);
  bool restore(Device& replacement,Time now);
};
}
