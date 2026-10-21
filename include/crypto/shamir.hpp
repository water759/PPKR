#pragma once
#include "crypto/oprf.hpp"
#include <vector>
namespace ppkr::shamir {
using Field=oprf::Scalar;
bool canonical(const Field& value);
Field coordinate(std::uint64_t index);
struct Share {
  Field x{},y{};
  ~Share();
};
// Coefficients are uniform in Z_q, including zero. Same q as Ristretto OPRF.
std::vector<Share> split(const Field& secret,std::size_t threshold,std::size_t count);
Field reconstruct(const std::vector<Share>& shares);
}
