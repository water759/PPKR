#pragma once
#include <array>
#include <cstdint>
#include <string>
#include <string_view>

namespace ppkr::oprf {
using Scalar = std::array<unsigned char, 32>;
using Point = std::array<unsigned char, 32>;
using Output = std::array<unsigned char, 32>;
enum class Domain { Device, Hsm };
// Call once before using this module, including from each standalone executable.
void initialize();
// Binary strings, no normalization. Encodes the pair unambiguously; see docs.
std::string encode_input(std::string_view password, std::string_view id);
Scalar random_scalar(); // uniform in Z_q^*, canonical little endian
Point hash_to_group(Domain domain, std::string_view x);
Output finalize(Domain domain, std::string_view x, const Point& evaluated);
// Device: a_D = H1(x)^k_D; rho_D = H2(x, a_D). No blinding round.
Output device_evaluate(std::string_view x, const Scalar& key);
// HSM branch: a_H = H3(x)^r; b_H = a_H^k; rho_H = H4(x, b_H^(1/r)).
Point hsm_blind(std::string_view x, const Scalar& blind);
Point hsm_evaluate(const Point& request, const Scalar& key);
Point hsm_unblind(const Point& response, const Scalar& blind);
Output hsm_finalize(std::string_view x, const Point& response, const Scalar& blind);
// Reference unblinded HSM function; not an extra protocol message.
Output hsm_direct(std::string_view x, const Scalar& key);
} // namespace ppkr::oprf
