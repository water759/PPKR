#include "crypto/shamir.hpp"
#include <sodium.h>
#include <set>
#include <stdexcept>
namespace ppkr::shamir {
namespace {
constexpr Field q{0xed,0xd3,0xf5,0x5c,0x1a,0x63,0x12,0x58,0xd6,0x9c,0xf7,0xa2,0xde,0xf9,0xde,0x14,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0x10};
struct Secret { Field v{}; ~Secret(){sodium_memzero(v.data(),v.size());} };
struct Polynomial { std::vector<Field> coefficients; ~Polynomial(){for(auto& c:coefficients)sodium_memzero(c.data(),c.size());} };
}
bool canonical(const Field& value){return sodium_compare(value.data(),q.data(),32)<0;}
Share::~Share(){sodium_memzero(y.data(),y.size());}
Field coordinate(std::uint64_t j){Field x{}; for(int i=0;i<8;++i)x[i]=(j>>(8*i))&255;return x;}
std::vector<Share> split(const Field& secret,std::size_t t,std::size_t n){
  if(!canonical(secret)||!t||t>n)throw std::invalid_argument("invalid Shamir parameters");
  Polynomial p; p.coefficients.resize(t);p.coefficients[0]=secret;
  for(std::size_t i=1;i<t;++i)crypto_core_ristretto255_scalar_random(p.coefficients[i].data());
  std::vector<Share> shares;shares.reserve(n);
  for(std::size_t j=1;j<=n;++j){
    Share share;share.x=coordinate(j);share.y=p.coefficients.back();
    for(std::size_t k=t-1;k>0;--k){
      crypto_core_ristretto255_scalar_mul(share.y.data(),share.y.data(),share.x.data());
      crypto_core_ristretto255_scalar_add(share.y.data(),share.y.data(),p.coefficients[k-1].data());
    }
    shares.push_back(share);
  }
  return shares;
}
Field reconstruct(const std::vector<Share>& shares){
  if(shares.empty())throw std::invalid_argument("no Shamir shares");
  std::set<Field> seen;
  for(const auto& s:shares)if(!canonical(s.x)||!canonical(s.y)||sodium_is_zero(s.x.data(),32)||!seen.insert(s.x).second)
    throw std::invalid_argument("invalid or repeated Shamir coordinate/share");
  Secret sum;
  for(std::size_t j=0;j<shares.size();++j){
    Secret num,den,delta,inverse,term;num.v[0]=den.v[0]=1;
    for(std::size_t k=0;k<shares.size();++k)if(k!=j){
      Field negative{};crypto_core_ristretto255_scalar_negate(negative.data(),shares[k].x.data());
      crypto_core_ristretto255_scalar_mul(num.v.data(),num.v.data(),negative.data());
      crypto_core_ristretto255_scalar_sub(delta.v.data(),shares[j].x.data(),shares[k].x.data());
      crypto_core_ristretto255_scalar_mul(den.v.data(),den.v.data(),delta.v.data());
    }
    if(crypto_core_ristretto255_scalar_invert(inverse.v.data(),den.v.data())!=0)throw std::invalid_argument("singular interpolation");
    crypto_core_ristretto255_scalar_mul(term.v.data(),num.v.data(),inverse.v.data());
    crypto_core_ristretto255_scalar_mul(term.v.data(),term.v.data(),shares[j].y.data());
    crypto_core_ristretto255_scalar_add(sum.v.data(),sum.v.data(),term.v.data());
  }
  return sum.v;
}
}
