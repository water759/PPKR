#pragma once
#include "evaluation/workload.hpp"
#include <set>
namespace ppkr::evaluation::wbp {
using crypto::Bytes;using crypto::Key;using crypto::Signature;
struct DhKeys {oprf::Scalar sk;oprf::Point pk;};
DhKeys dh_keygen();
oprf::Point dh(const oprf::Scalar& sk,const oprf::Point& pk);
Key mac(std::string_view key,const Bytes& message);
Bytes hkdf(const Bytes& ikm,const Bytes& salt,const Bytes& info,std::size_t length);
struct Keys {Key first,second,third;};
struct Request {oprf::Scalar blind;oprf::Point a;Key nonce;DhKeys ephemeral;};
struct Reply {oprf::Point b;Key masked,nonce,tag,server_nonce;oprf::Point ephemeral;Key server_tag{};Signature signature{};};
struct Proof {Key tag,export_key,session_key;}; // local state; only tag is sent
class Workload {
  Config config;
  bool concrete_attestation;
  DhKeys server_dh=dh_keygen();
  crypto::EncryptionKeys server_enc=crypto::encryption_keygen();
  crypto::SigningKeys server_sig=crypto::signing_from_seed(crypto::random_key());
  struct Pending {Key client_mac,session_key,server_tag;Bytes preamble;};
  std::optional<Pending> pending;
  std::optional<Key> original,recovered;
  std::set<Key> tombstones;
  std::optional<Key> account;
public:
  struct Record {Key aid;oprf::Scalar oprf_key;Bytes envelope;oprf::Point client_public;Key masked,nonce,tag;std::uint64_t counter=10;};
  std::optional<Record> record;
  explicit Workload(Config c={},bool signatures=false):config(std::move(c)),concrete_attestation(signatures){}
  void initialize(Traffic* traffic=nullptr);
  Request client_start(std::string_view password)const;
  std::optional<Reply> hsm_start(const Request& request);
  std::optional<Proof> client_authenticate(std::string_view password,const Request& request,const Reply& reply)const;
  std::optional<Bytes> hsm_finish(const Key& client_tag);
  bool client_finish(const Proof& proof,const Bytes& ciphertext);
  bool recover(std::string_view password,Traffic* traffic=nullptr);
  void setup(Stage stage);
  void run(Stage stage,Traffic* traffic=nullptr);
  void validate(Stage stage)const;
  Storage storage(Stage stage)const;
};
class AttestedWorkload:public Workload {
public:explicit AttestedWorkload(Config c={}):Workload(std::move(c),true){}
};
}
