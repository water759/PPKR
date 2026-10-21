#include "crypto/oprf.hpp"
#include <sodium.h>
#include <openssl/sha.h>
#include <openssl/bn.h>
#include <memory>
#include <algorithm>
#include <iostream>
#include <stdexcept>
#include <vector>
using namespace ppkr::oprf;
namespace {
int checks = 0;
std::string hex(const Point& p) {
  static constexpr char digits[]="0123456789abcdef";
  std::string out; for(auto b:p) {out+=digits[b>>4];out+=digits[b&15];} return out;
}
void check(bool b) { ++checks; if (!b) throw std::runtime_error("check " + std::to_string(checks) + " failed"); }
template<class F> void reject(F f) {
  bool rejected=false; try { f(); } catch(const std::invalid_argument&) { rejected=true; }
  check(rejected);
}
// Independent transcript serialization and SHA-512 provider, bypassing production hash helpers.
void field(std::vector<unsigned char>& m, std::string_view s) {
  for(int i=7;i>=0;--i) m.push_back((static_cast<std::uint64_t>(s.size())>>(8*i))&255);
  m.insert(m.end(),s.begin(),s.end());
}
// Test-only independent scalar inversion; never used by production OPRF.
Point reference_unblind(const Point& b, const Scalar& r) {
  using Big = std::unique_ptr<BIGNUM, decltype(&BN_clear_free)>;
  using Context = std::unique_ptr<BN_CTX, decltype(&BN_CTX_free)>;
  // Decimal q independently specifies the field, rather than copying LE order bytes.
  BIGNUM* raw_order=nullptr;
  if (!BN_dec2bn(&raw_order,"7237005577332262213973186563042994240857116359379907606001950938285454250989"))
    throw std::runtime_error("reference order allocation failed");
  Big order(raw_order,BN_clear_free);
  Big scalar(BN_lebin2bn(r.data(),r.size(),nullptr),BN_clear_free);
  Context ctx(BN_CTX_new(),BN_CTX_free);
  if (!scalar || !ctx) throw std::runtime_error("reference allocation failed");
  Big inverse(BN_mod_inverse(nullptr,scalar.get(),order.get(),ctx.get()),BN_clear_free);
  if (!inverse) throw std::runtime_error("reference inversion failed");
  Scalar bytes{};
  check(BN_bn2lebinpad(inverse.get(),bytes.data(),bytes.size())==static_cast<int>(bytes.size()));
  Point result{};
  check(crypto_scalarmult_ristretto255(result.data(),bytes.data(),b.data())==0);
  return result;
}
Output reference(std::string_view x, const Scalar& k, bool device) {
  std::vector<unsigned char> m; field(m,device?"PPKR-2HashDH-v1/H1":"PPKR-2HashDH-v1/H3"); field(m,x);
  unsigned char h[64]; SHA512(m.data(),m.size(),h); Point p{}, z{};
  check(crypto_core_ristretto255_from_hash(p.data(),h)==0);
  check(crypto_scalarmult_ristretto255(z.data(),k.data(),p.data())==0);
  m.clear(); field(m,device?"PPKR-2HashDH-v1/H2":"PPKR-2HashDH-v1/H4"); field(m,x);
  field(m,std::string_view(reinterpret_cast<const char*>(z.data()),z.size()));
  SHA512(m.data(),m.size(),h); Output out{}; std::copy(h,h+32,out.begin()); return out;
}
}
int main() {
try {
  initialize(); Scalar one{}; one[0]=1; Scalar two{}; two[0]=2;
  const auto x=encode_input("password","alice");
  // Regression vectors produced with Python hashlib plus the libsodium map, k=1.
  check(hex(hash_to_group(Domain::Device,x))=="544642e3a865535178d77eaa5644d3ed98981b9cf34c569dddc234cd63f3c769");
  check(hex(device_evaluate(x,one))=="f8c797955d44a3932f9689a9998ba18dade2243041092681df201056799c601e");
  check(hex(hash_to_group(Domain::Hsm,x))=="e6ab9bb35cc6dbcad33242be97fdc1c95f7e6f80c96219a6ac2d156d815db51e");
  check(hex(hsm_direct(x,one))=="9b0d30f3d6b87ac2af2a6b099e5821bf7f203b7087b5b8e46f2c846fb8014271");
  check(x!=encode_input("passwor","dalice"));
  check(encode_input("ab","c")!=encode_input("a","bc"));
  check(encode_input(std::string("a\0b",3),"c")!=encode_input("a","c"));
  check(encode_input("","").size()==16);
  const auto encoded=encode_input(std::string(256,'p'),"i");
  check(encoded.size()==273);
  check(static_cast<unsigned char>(encoded[6])==1 && encoded[7]==0);
  check(static_cast<unsigned char>(encoded[271])==1 && encoded[272]=='i');
  // Valid but altered replies remain valid group elements: this is not a VOPRF.
  const auto req=hsm_blind(x,one);
  const auto reply=hsm_evaluate(req,two);
  check(hsm_finalize(x,reply,one)==hsm_direct(x,two));
  check(hsm_finalize(x,reply,one)!=hsm_direct(x,one));
  check(hsm_finalize(x,reply,two)!=hsm_finalize(x,reply,one));
  std::vector<std::string> inputs{"",x,encode_input("","id"),encode_input("pw",""),
    encode_input(std::string("p\0w",3), std::string("i\0d",3)),encode_input("口令","用户"),std::string(4096,'x')};
  for(const auto& input:inputs) for(int i=0;i<40;++i) {
    const auto k=i==0?one:random_scalar(); const auto r=i==0?one:random_scalar();
    const auto a=hsm_blind(input,r); const auto b=hsm_evaluate(a,k);
    const auto z=hsm_unblind(b,r); Point expected{};
    auto p=hash_to_group(Domain::Hsm,input);
    check(crypto_scalarmult_ristretto255(expected.data(),k.data(),p.data())==0);
    check(z==expected);
    check(z==reference_unblind(b,r));
    const auto out=hsm_finalize(input,b,r);
    check(out==hsm_direct(input,k)); check(out==reference(input,k,false));
    check(device_evaluate(input,k)==reference(input,k,true));
    check(device_evaluate(input,k)==device_evaluate(input,k));
    check(device_evaluate(input,k)!=out);
    const auto r2=random_scalar();
    check(hsm_finalize(input,hsm_evaluate(hsm_blind(input,r2),k),r2)==out);
    check(hsm_direct(input,k)!=hsm_direct(input,k==one?two:one));
    check(out!=hsm_direct(input+"!",k));
  }
  check(hash_to_group(Domain::Device,x)!=hash_to_group(Domain::Hsm,x));
  auto p=hash_to_group(Domain::Hsm,x);
  check(finalize(Domain::Device,x,p)!=finalize(Domain::Hsm,x,p));
  Scalar zero{}, noncanonical{}; noncanonical.fill(255);
  Scalar q{0xed,0xd3,0xf5,0x5c,0x1a,0x63,0x12,0x58,0xd6,0x9c,0xf7,0xa2,0xde,0xf9,0xde,0x14,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0x10};
  auto last=q; --last[0];
  check(hsm_finalize(x,hsm_evaluate(hsm_blind(x,last),last),last)==hsm_direct(x,last));
  check(device_evaluate(x,last)==reference(x,last,true));
  const auto last_reply=hsm_evaluate(hsm_blind(x,last),last);
  check(hsm_unblind(last_reply,last)==reference_unblind(last_reply,last));
  for(const auto& bad:{zero,q,noncanonical}) {
    reject([&]{device_evaluate(x,bad);}); reject([&]{hsm_blind(x,bad);});
    reject([&]{hsm_evaluate(p,bad);}); reject([&]{hsm_unblind(p,bad);});
    reject([&]{hsm_direct(x,bad);});
  }
  Point identity{}, invalid{}; invalid.fill(255);
  for(const auto& bad:{identity,invalid}) {
    reject([&]{hsm_evaluate(bad,one);}); reject([&]{hsm_unblind(bad,one);});
    reject([&]{hsm_finalize(x,bad,one);}); reject([&]{finalize(Domain::Device,x,bad);});
  }
  reject([&]{hash_to_group(static_cast<Domain>(99),x);});
  reject([&]{finalize(static_cast<Domain>(99),x,p);});
  std::cout<<"PASS: "<<checks<<" checks; 280 randomized/boundary cases\n";
  return 0;
} catch(const std::exception& e) { std::cerr<<"FAIL: "<<e.what()<<'\n'; return 1; }
}
