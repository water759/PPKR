#include "protocol/core.hpp"
#include <stdexcept>
#include <algorithm>
#include <limits>
namespace ppkr::protocol {
namespace {
void check_policy(const Policy& p) {
  if(p.delta==0 || p.limit==0) throw std::invalid_argument("positive window and limit required");
}
void reset_window(Window& w,Time now,const Policy& p) {
  check_policy(p);
  if(now<w.start) throw std::invalid_argument("logical time must be monotonic");
  if(now-w.start>=p.delta) w={0,now};
}
// Only initialization's decrypted tuple is decoded here. Strict bounds and no trailing bytes.
std::optional<std::vector<Bytes>> decode_tuple(const Bytes& msg,std::size_t count) {
  std::size_t pos=0; std::vector<Bytes> out;
  for(std::size_t i=0;i<count;++i) {
    if(msg.size()-pos<8) return std::nullopt;
    std::uint64_t n=0; for(int j=0;j<8;++j) n=(n<<8)|msg[pos++];
    if(n>msg.size()-pos) return std::nullopt;
    out.emplace_back(msg.begin()+pos,msg.begin()+pos+static_cast<std::size_t>(n)); pos+=n;
  }
  if(pos!=msg.size()) return std::nullopt;
  return out;
}
}
std::pair<DeviceInit,InitRequest> Device::begin_init(std::string id,std::string_view pw) {
  if(records.count(id)) throw std::invalid_argument("initialization requires fresh ID");
  DeviceInit p{}; p.id=std::move(id); p.x=oprf::encode_input(pw,p.id);
  p.key=oprf::random_scalar(); p.rho_d=oprf::device_evaluate(p.x,p.key);
  p.file_key=crypto::random_key(); p.blind=oprf::random_scalar();
  InitRequest request{oprf::hsm_blind(p.x,p.blind),p.id};
  return {std::move(p),std::move(request)};
}
InitResponse Hsm::begin_init(const InitRequest& request) {
  if(records.count(request.id) || init_pending.count(request.id))
    throw std::invalid_argument("initialization requires fresh ID");
  auto enc=crypto::encryption_keygen();
  InitPending p{oprf::random_scalar(),std::move(enc)};
  InitResponse result{oprf::hsm_evaluate(request.a,p.key),p.enc.pk,request.id};
  init_pending.emplace(request.id,std::move(p)); return result;
}
InitUpload Device::finish_init_crypto(DeviceInit& p,const InitResponse& response) {
  if(p.terminal || p.uploaded || response.id!=p.id) throw std::invalid_argument("unexpected init response");
  const auto rho_h=oprf::hsm_finalize(p.x,response.b,p.blind);
  const auto derived=crypto::derive(p.rho_d,rho_h);
  const auto mk=crypto::random_key();
  const auto cf=crypto::ae_encrypt(crypto::bytes(p.file_key),mk);
  const auto cmk=crypto::ae_encrypt(crypto::bytes(mk),derived.kek);
  const auto tuple=crypto::encode({crypto::view(cmk),crypto::view(cf),crypto::view(derived.signing.pk)});
  auto ciphertext=crypto::pke_encrypt(tuple,response.pk_enc); p.uploaded=true;
  return {std::move(ciphertext)};
}
InitResult Hsm::accept_init(const std::string& id,const InitUpload& upload,Time now) {
  auto it=init_pending.find(id); if(it==init_pending.end()) return {false};
  auto p=std::move(it->second); init_pending.erase(it);
  const auto plaintext=crypto::pke_decrypt(upload.ciphertext,p.enc);
  if(!plaintext) return {false};
  const auto fields=decode_tuple(*plaintext,3);
  if(!fields || (*fields)[2].size()!=32) return {false};
  records.emplace(id,HsmRecord{(*fields)[0],(*fields)[1],crypto::key_from_bytes((*fields)[2]),p.key,{0,now}});
  return {true};
}
std::optional<Key> Device::accept_init(DeviceInit& p,const InitResult& result,Time now) {
  if(p.terminal) return std::nullopt;
  p.terminal=true;
  if(!result.success || !p.uploaded || records.count(p.id)) return std::nullopt;
  records.emplace(p.id,DeviceRecord{p.key,{0,now}}); return p.file_key;
}
std::optional<std::pair<DeviceRecovery,RecRequest>> Device::begin_recovery(
    const std::string& id,std::string_view pw,Time now) {
  auto it=records.find(id); if(it==records.end()) return std::nullopt;
  auto& record=it->second; reset_window(record.window,now,policy);
  if(record.window.counter>=policy.limit) return std::nullopt;
  ++record.window.counter;
  DeviceRecovery p{}; p.id=id; p.x=oprf::encode_input(pw,id);
  p.rho_d=oprf::device_evaluate(p.x,record.key); p.blind=oprf::random_scalar();
  p.a=oprf::hsm_blind(p.x,p.blind); RecRequest request{p.a,id};
  return std::make_pair(std::move(p),std::move(request));
}
std::optional<RecResponse> Hsm::begin_recovery(const RecRequest& request,Time now) {
  auto it=records.find(request.id); if(it==records.end()) return std::nullopt;
  // Sequential admitted executions only; do not silently overwrite an active call.
  if(rec_pending.count(request.id)) throw std::invalid_argument("recovery already active");
  auto& record=it->second; reset_window(record.window,now,policy);
  if(record.window.counter>=policy.limit) return std::nullopt;
  RecPending p{request.a,oprf::hsm_evaluate(request.a,record.key),crypto::random_key()};
  RecResponse response{p.b,record.cmk,p.nonce,request.id}; rec_pending.emplace(request.id,p); return response;
}
Bytes authentication_message(const Point& a,const Point& b,const std::string& id,const Key& nonce) {
  return crypto::encode({"RecAuth",crypto::view(a),crypto::view(b),id,crypto::view(nonce)});
}
std::optional<RecAuth> Device::authenticate(DeviceRecovery& p,const RecResponse& response) {
  if(p.terminal || p.derived) return std::nullopt;
  if(response.id!=p.id) { p.terminal=true; return std::nullopt; }
  const auto rho_h=oprf::hsm_finalize(p.x,response.b,p.blind);
  p.derived=crypto::derive(p.rho_d,rho_h); p.cmk=response.cmk;
  return RecAuth{crypto::sign(authentication_message(p.a,response.b,p.id,response.nonce),p.derived->signing)};
}
RecResult Hsm::authenticate(const std::string& id,const RecAuth& auth) {
  auto it=rec_pending.find(id); if(it==rec_pending.end()) return {false,std::nullopt};
  auto p=it->second; rec_pending.erase(it); auto record=records.find(id);
  if(record==records.end()) return {false,std::nullopt};
  auto& r=record->second;
  if(!crypto::verify(authentication_message(p.a,p.b,id,p.nonce),auth.signature,r.pk_c)) {
    // A pending call began below L; at most one sequential increment follows it.
    ++r.window.counter; return {false,std::nullopt};
  }
  return {true,r.cf};
}
std::optional<Key> Device::recover(DeviceRecovery& p,const RecResult& result) {
  if(p.terminal) return std::nullopt;
  p.terminal=true;
  if(!p.derived || !p.cmk) return std::nullopt;
  auto derived=std::move(*p.derived); p.derived.reset();
  auto cmk=std::move(*p.cmk); p.cmk.reset();
  if(!result.success || !result.ciphertext) return std::nullopt;
  auto mk=crypto::ae_decrypt(cmk,derived.kek); if(!mk || mk->size()!=32) return std::nullopt;
  auto fk=crypto::ae_decrypt(*result.ciphertext,crypto::key_from_bytes(*mk));
  if(!fk || fk->size()!=32) return std::nullopt;
  return crypto::key_from_bytes(*fk);
}
Bytes deliver_key(const Key& key,const Key& pk) { return crypto::pke_encrypt(crypto::bytes(key),pk); }
std::optional<Key> Client::receive(const Bytes& delivery) const {
  auto m=crypto::pke_decrypt(delivery,keys); if(!m || m->size()!=32) return std::nullopt;
  return crypto::key_from_bytes(*m);
}
}
