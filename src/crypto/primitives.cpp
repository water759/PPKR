#include "crypto/primitives.hpp"
#include <sodium.h>
#include <algorithm>
#include <stdexcept>
namespace ppkr::crypto {
std::string_view view(const Bytes& b) { return {reinterpret_cast<const char*>(b.data()),b.size()}; }
Bytes encode(std::initializer_list<std::string_view> fields) {
  Bytes out;
  for(auto f:fields) {
    const auto n=static_cast<std::uint64_t>(f.size());
    for(int i=7;i>=0;--i) out.push_back((n>>(8*i))&255);
    if(!f.empty()) out.insert(out.end(),f.begin(),f.end());
  }
  return out;
}
namespace {
Key hash(std::string_view domain, const Bytes& input) {
  auto msg=encode({domain,view(input)}); std::array<unsigned char,64> digest{};
  crypto_hash_sha512(digest.data(),msg.data(),msg.size()); Key out{};
  std::copy_n(digest.begin(),out.size(),out.begin());
  sodium_memzero(msg.data(),msg.size()); sodium_memzero(digest.data(),digest.size()); return out;
}
}
Key random_key() { Key key{}; randombytes_buf(key.data(),key.size()); return key; }
Key hash_root(std::initializer_list<std::string_view> f) { return hash("PPKR-v1/Hroot",encode(f)); }
Key hash_kek(std::initializer_list<std::string_view> f) { return hash("PPKR-v1/HKEK",encode(f)); }
SigningKeys signing_from_seed(const Key& seed) {
  SigningKeys k{}; if(crypto_sign_seed_keypair(k.pk.data(),k.sk.data(),seed.data())!=0)
    throw std::runtime_error("signing key generation failed");
  return k;
}
Derived derive(const Key& d,const Key& h) {
  auto root=hash_root({"root",view(d),view(h)});
  auto seed=hash_root({"hsm-sig",view(root)});
  Derived out{hash_kek({"kek",view(root)}),signing_from_seed(seed)};
  sodium_memzero(root.data(),root.size()); sodium_memzero(seed.data(),seed.size()); return out;
}
Signature sign(const Bytes& m,const SigningKeys& k) {
  Signature s{}; if(crypto_sign_detached(s.data(),nullptr,m.data(),m.size(),k.sk.data())!=0)
    throw std::runtime_error("signing failed");
  return s;
}
bool verify(const Bytes& m,const Signature& s,const Key& pk) {
  return crypto_sign_verify_detached(s.data(),m.data(),m.size(),pk.data())==0;
}
EncryptionKeys encryption_keygen() {
  EncryptionKeys k{}; if(crypto_box_keypair(k.pk.data(),k.sk.data())!=0)
    throw std::runtime_error("encryption key generation failed");
  return k;
}
Bytes pke_encrypt(const Bytes& m,const Key& pk) {
  Bytes c(m.size()+crypto_box_SEALBYTES);
  if(crypto_box_seal(c.data(),m.data(),m.size(),pk.data())!=0)
    throw std::invalid_argument("invalid PKE public key");
  return c;
}
std::optional<Bytes> pke_decrypt(const Bytes& c,const EncryptionKeys& k) {
  if(c.size()<crypto_box_SEALBYTES) return std::nullopt;
  Bytes m(c.size()-crypto_box_SEALBYTES);
  if(crypto_box_seal_open(m.data(),c.data(),c.size(),k.pk.data(),k.sk.data())!=0) return std::nullopt;
  return m;
}
Bytes ae_encrypt(const Bytes& m,const Key& k) {
  constexpr auto n=crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
  Bytes c(n+m.size()+crypto_aead_xchacha20poly1305_ietf_ABYTES);
  randombytes_buf(c.data(),n);
  if(crypto_aead_xchacha20poly1305_ietf_encrypt(c.data()+n,nullptr,m.data(),m.size(),
      nullptr,0,nullptr,c.data(),k.data())!=0) throw std::runtime_error("AE failed");
  return c;
}
std::optional<Bytes> ae_decrypt(const Bytes& c,const Key& k) {
  constexpr auto n=crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
  if(c.size()<n+crypto_aead_xchacha20poly1305_ietf_ABYTES) return std::nullopt;
  Bytes m(c.size()-n-crypto_aead_xchacha20poly1305_ietf_ABYTES);
  if(crypto_aead_xchacha20poly1305_ietf_decrypt(m.data(),nullptr,nullptr,c.data()+n,c.size()-n,
      nullptr,0,c.data(),k.data())!=0) return std::nullopt;
  return m;
}
Key key_from_bytes(const Bytes& b) {
  if(b.size()!=32) throw std::invalid_argument("expected 32-byte key");
  Key k{}; std::copy(b.begin(),b.end(),k.begin());
  return k;
}
Bytes bytes(const Key& k) { return {k.begin(),k.end()}; }
}
