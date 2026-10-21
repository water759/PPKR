#pragma once
#include "crypto/oprf.hpp"
#include "crypto/primitives.hpp"
#include <cstdint>
#include <map>
namespace ppkr::protocol {
using crypto::Bytes; using crypto::Key; using oprf::Point; using oprf::Scalar;
// Logical seconds supplied by the harness: no sleep, network, or hardware claim.
using Time = std::uint64_t;
struct Policy { Time delta=60; std::uint64_t limit=5; };
struct Window { std::uint64_t counter=0; Time start=0; };
struct DeviceRecord { Scalar key; Window window; };
struct HsmRecord { Bytes cmk, cf; Key pk_c; Scalar key; Window window; };
struct InitRequest { Point a; std::string id; };
struct InitResponse { Point b; Key pk_enc; std::string id; };
struct InitUpload { Bytes ciphertext; };
struct InitResult { bool success; };
struct RecRequest { Point a; std::string id; };
struct RecResponse { Point b; Bytes cmk; Key nonce; std::string id; };
struct RecAuth { crypto::Signature signature; };
struct RecResult { bool success; std::optional<Bytes> ciphertext; };
// Local temporary states. These are not transmitted or serialized as messages.
struct DeviceInit { std::string id,x; Scalar key,blind; Key rho_d,file_key; bool uploaded=false,terminal=false; };
struct DeviceRecovery { std::string id,x; Scalar blind; Point a; Key rho_d;
  bool terminal=false; std::optional<crypto::Derived> derived; std::optional<Bytes> cmk; };
struct Device {
  Policy policy;
  std::map<std::string,DeviceRecord> records;
  std::pair<DeviceInit,InitRequest> begin_init(std::string id,std::string_view pw);
  InitUpload finish_init_crypto(DeviceInit& pending,const InitResponse& response);
  std::optional<Key> accept_init(DeviceInit& pending,const InitResult& result,Time now);
  std::optional<std::pair<DeviceRecovery,RecRequest>> begin_recovery(const std::string& id,std::string_view pw,Time now);
  std::optional<RecAuth> authenticate(DeviceRecovery& pending,const RecResponse& response);
  std::optional<Key> recover(DeviceRecovery& pending,const RecResult& result);
};
struct Hsm {
  Policy policy;
  std::map<std::string,HsmRecord> records;
  InitResponse begin_init(const InitRequest& request);
  InitResult accept_init(const std::string& id,const InitUpload& upload,Time now);
  std::optional<RecResponse> begin_recovery(const RecRequest& request,Time now);
  RecResult authenticate(const std::string& id,const RecAuth& auth);
private:
  struct InitPending { Scalar key; crypto::EncryptionKeys enc; };
  struct RecPending { Point a,b; Key nonce; };
  std::map<std::string,InitPending> init_pending;
  std::map<std::string,RecPending> rec_pending;
};
// S only relays prescribed messages for this honest sequential implementation.
struct Server { template<class Message> Message relay(const Message& m) const { return m; } };
Bytes authentication_message(const Point& a,const Point& b,const std::string& id,const Key& nonce);
struct Client {
  crypto::EncryptionKeys keys=crypto::encryption_keygen();
  Key qr_public_key() const { return keys.pk; }
  std::optional<Key> receive(const Bytes& delivery) const;
};
// Argument is the exact pk obtained by scanning C's QR; QR hardware is abstracted.
Bytes deliver_key(const Key& file_key,const Key& scanned_public_key);
}
