#include "crypto/oprf.hpp"
#include <sodium.h>
#include <stdexcept>
#include <algorithm>

namespace ppkr::oprf {
namespace {
// Ristretto scalar order, little endian.
constexpr Scalar order{0xed,0xd3,0xf5,0x5c,0x1a,0x63,0x12,0x58,
  0xd6,0x9c,0xf7,0xa2,0xde,0xf9,0xde,0x14,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0x10};
void scalar_check(const Scalar& s) {
  if (sodium_is_zero(s.data(), s.size()) || sodium_compare(s.data(), order.data(), s.size()) >= 0)
    throw std::invalid_argument("scalar must be canonical and nonzero");
}
void point_check(const Point& p) {
  if (!crypto_core_ristretto255_is_valid_point(p.data()) || sodium_is_zero(p.data(), p.size()))
    throw std::invalid_argument("point must be canonical and nonidentity");
}
void domain_check(Domain d) {
  if (d != Domain::Device && d != Domain::Hsm) throw std::invalid_argument("invalid OPRF domain");
}
void length(std::string& out, std::size_t n) {
  static_assert(sizeof(std::size_t) <= sizeof(std::uint64_t));
  const auto v = static_cast<std::uint64_t>(n);
  for (int i = 7; i >= 0; --i) out.push_back(static_cast<char>((v >> (8*i)) & 255));
}
void field(std::string& out, std::string_view v) {
  length(out, v.size()); out.append(v);
}
std::array<unsigned char,64> hash(std::string_view tag, std::string_view x,
                                  const Point* p = nullptr) {
  std::string msg; field(msg, tag); field(msg, x);
  if (p) field(msg, std::string_view(reinterpret_cast<const char*>(p->data()), p->size()));
  std::array<unsigned char,64> digest{};
  crypto_hash_sha512(digest.data(), reinterpret_cast<const unsigned char*>(msg.data()), msg.size());
  sodium_memzero(msg.data(), msg.size());
  return digest;
}
Point multiply(const Point& p, const Scalar& s) {
  scalar_check(s); point_check(p); Point out{};
  if (crypto_scalarmult_ristretto255(out.data(), s.data(), p.data()) != 0)
    throw std::runtime_error("Ristretto multiplication failed");
  return out;
}
struct WipedScalar { Scalar value{}; ~WipedScalar() { sodium_memzero(value.data(), value.size()); } };
}
void initialize() { if (sodium_init() < 0) throw std::runtime_error("sodium_init failed"); }
std::string encode_input(std::string_view pw, std::string_view id) {
  std::string x; field(x, pw); field(x, id); return x;
}
Scalar random_scalar() {
  Scalar s{};
  do { crypto_core_ristretto255_scalar_random(s.data()); } while (sodium_is_zero(s.data(), s.size()));
  return s;
}
Point hash_to_group(Domain d, std::string_view x) {
  domain_check(d);
  auto h = hash(d == Domain::Device ? "PPKR-2HashDH-v1/H1" : "PPKR-2HashDH-v1/H3", x);
  Point p{}; crypto_core_ristretto255_from_hash(p.data(), h.data());
  // No silent rehash/retry: identity would make libsodium scalar multiplication fail.
  point_check(p); return p;
}
Output finalize(Domain d, std::string_view x, const Point& p) {
  domain_check(d); point_check(p);
  auto h = hash(d == Domain::Device ? "PPKR-2HashDH-v1/H2" : "PPKR-2HashDH-v1/H4", x, &p);
  Output out{}; std::copy_n(h.begin(), out.size(), out.begin()); return out;
}
Output device_evaluate(std::string_view x, const Scalar& k) {
  return finalize(Domain::Device, x, multiply(hash_to_group(Domain::Device, x), k));
}
Point hsm_blind(std::string_view x, const Scalar& r) { return multiply(hash_to_group(Domain::Hsm, x), r); }
Point hsm_evaluate(const Point& a, const Scalar& k) { return multiply(a, k); }
Point hsm_unblind(const Point& b, const Scalar& r) {
  scalar_check(r); WipedScalar inv;
  if (crypto_core_ristretto255_scalar_invert(inv.value.data(), r.data()) != 0)
    throw std::invalid_argument("noninvertible blinding scalar");
  return multiply(b, inv.value);
}
Output hsm_finalize(std::string_view x, const Point& b, const Scalar& r) {
  return finalize(Domain::Hsm, x, hsm_unblind(b, r));
}
Output hsm_direct(std::string_view x, const Scalar& k) {
  return finalize(Domain::Hsm, x, multiply(hash_to_group(Domain::Hsm, x), k));
}
}
