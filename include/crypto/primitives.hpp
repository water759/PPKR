#pragma once
#include <array>
#include <cstdint>
#include <initializer_list>
#include <optional>
#include <string>
#include <string_view>
#include <vector>
namespace ppkr::crypto {
using Bytes = std::vector<unsigned char>;
using Key = std::array<unsigned char,32>;
using Signature = std::array<unsigned char,64>;
struct SigningKeys { Key pk; std::array<unsigned char,64> sk; };
struct EncryptionKeys { Key pk, sk; };
std::string_view view(const Bytes& b);
template<std::size_t N> std::string_view view(const std::array<unsigned char,N>& b) {
  return {reinterpret_cast<const char*>(b.data()),b.size()};
}
// uint64_be length-prefixed fields, including labels, no implicit terminator.
Bytes encode(std::initializer_list<std::string_view> fields);
Key random_key();
Key hash_root(std::initializer_list<std::string_view> fields);
Key hash_kek(std::initializer_list<std::string_view> fields);
struct Derived { Key kek; SigningKeys signing; };
Derived derive(const Key& rho_d, const Key& rho_h);
SigningKeys signing_from_seed(const Key& seed);
Signature sign(const Bytes& msg, const SigningKeys& keys);
bool verify(const Bytes& msg, const Signature& sig, const Key& pk);
EncryptionKeys encryption_keygen();
Bytes pke_encrypt(const Bytes& msg, const Key& pk);
std::optional<Bytes> pke_decrypt(const Bytes& ciphertext, const EncryptionKeys& keys);
Bytes ae_encrypt(const Bytes& msg, const Key& key);
std::optional<Bytes> ae_decrypt(const Bytes& ciphertext, const Key& key);
Key key_from_bytes(const Bytes& bytes);
Bytes bytes(const Key& key);
}
