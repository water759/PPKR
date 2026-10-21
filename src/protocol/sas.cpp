#include "protocol/sas.hpp"
#include <sodium.h>
#include <algorithm>
#include <stdexcept>
namespace ppkr::protocol {
namespace {
void parameters(unsigned k){if(k<1||k>256)throw std::invalid_argument("SAS length must be 1..256 bits");}
bool canonical(const ShortCode& code,unsigned bits){
  if(code.bits!=bits||code.value.size()!=(bits+7)/8)return false;
  return bits%8==0 || (code.value[0]>>(bits%8))==0;
}
ShortCode sample(unsigned k){
  ShortCode r{k,crypto::Bytes((k+7)/8)};randombytes_buf(r.value.data(),r.value.size());
  if(k%8)r.value[0]&=(1u<<(k%8))-1;
  return r;
}
ShortCode exclusive_or(const ShortCode& a,const ShortCode& b){
  ShortCode out=a;for(std::size_t i=0;i<out.value.size();++i)out.value[i]^=b.value[i];return out;
}
crypto::Key digest(unsigned k,const crypto::Bytes& m,const ShortCode& r,const crypto::Key& e){
  std::string length(8,'\0');for(int i=0;i<8;++i)length[7-i]=(static_cast<std::uint64_t>(k)>>(8*i))&255;
  auto input=crypto::encode({"PPKR-SAS-v1/commit",length,crypto::view(m),crypto::view(r.value),crypto::view(e)});
  std::array<unsigned char,64> h{};crypto_hash_sha512(h.data(),input.data(),input.size());
  crypto::Key c{};std::copy_n(h.begin(),c.size(),c.begin());
  sodium_memzero(input.data(),input.size());sodium_memzero(h.data(),h.size());return c;
}
void wipe(ShortCode& c){if(!c.value.empty())sodium_memzero(c.value.data(),c.value.size());}
}
std::string format_code(const ShortCode& c){
  parameters(c.bits);if(!canonical(c,c.bits))throw std::invalid_argument("noncanonical short code");
  static constexpr char hex[]="0123456789abcdef";std::string text;
  for(auto b:c.value){text+=hex[b>>4];text+=hex[b&15];}
  return text.substr(text.size()-(c.bits+3)/4);
}
std::optional<ShortCode> parse_code(std::string_view text,unsigned bits){
  parameters(bits);if(text.size()!=(bits+3)/4)return std::nullopt;
  ShortCode code{bits,crypto::Bytes((bits+7)/8)};
  auto nibble=[](char c)->int{if(c>='0'&&c<='9')return c-'0';if(c>='a'&&c<='f')return c-'a'+10;if(c>='A'&&c<='F')return c-'A'+10;return -1;};
  const auto offset=2*code.value.size()-text.size();
  for(std::size_t i=0;i<text.size();++i){int n=nibble(text[i]);if(n<0)return std::nullopt;
    code.value[(offset+i)/2]|=static_cast<unsigned char>(n<<(((offset+i)%2)?0:4));}
  if(!canonical(code,bits))return std::nullopt;
  return code;
}
SasSender::SasSender(crypto::Bytes m,SasParameters p):params(p),message(std::move(m)),random{p.bits,{}}{parameters(p.bits);}
void SasSender::erase(){wipe(random);sodium_memzero(salt.data(),salt.size());}
SasSender::~SasSender(){erase();}
SasCommitment SasSender::begin(){
  if(state!=State::Fresh)throw std::logic_error("SAS sender already started");
  random=sample(params.bits);salt=crypto::random_key();state=State::Committed;
  return {message,digest(params.bits,message,random,salt),params.bits};
}
std::optional<SasOpening> SasSender::open(const SasChallenge& challenge){
  if(state!=State::Committed)return std::nullopt;
  state=State::Done;
  if(!canonical(challenge.random,params.bits)){erase();return std::nullopt;}
  code=exclusive_or(random,challenge.random);SasOpening opening{random,salt};erase();return opening;
}
SasVerifier::SasVerifier(SasParameters p):params(p),challenge{p.bits,{}}{parameters(p.bits);}
SasVerifier::~SasVerifier(){wipe(challenge);}
std::optional<SasChallenge> SasVerifier::receive(const SasCommitment& commitment){
  if(state!=State::Fresh)return std::nullopt;
  state=State::Done;
  if(commitment.bits!=params.bits)return std::nullopt;
  incoming=commitment;challenge=sample(params.bits);state=State::Challenged;return SasChallenge{challenge};
}
bool SasVerifier::receive(const SasOpening& opening){
  if(state!=State::Challenged)return false;
  state=State::Done;
  if(!canonical(opening.random,params.bits)){wipe(challenge);return false;}
  auto c=digest(params.bits,incoming->message,opening.random,opening.salt);
  if(sodium_memcmp(c.data(),incoming->commitment.data(),c.size())!=0){wipe(challenge);return false;}
  expected=exclusive_or(opening.random,challenge);wipe(challenge);state=State::AwaitingHuman;return true;
}
std::optional<AuthenticatedMessage> SasVerifier::confirm(const ShortCode& code,bool user_confirms){
  if(state!=State::AwaitingHuman)return std::nullopt;
  state=State::Done;
  if(!user_confirms||!canonical(code,params.bits)||sodium_memcmp(code.value.data(),expected->value.data(),code.value.size())!=0)
    return std::nullopt;
  return AuthenticatedMessage(incoming->message);
}
}
