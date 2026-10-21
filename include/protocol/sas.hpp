#pragma once
#include "crypto/primitives.hpp"
namespace ppkr::protocol {
// Vaudenay CRYPTO 2005, Figure 5; no authenticated-channel transport is provided.
struct SasParameters { unsigned bits=20; };
struct ShortCode { unsigned bits; crypto::Bytes value; };
struct SasCommitment { crypto::Bytes message; crypto::Key commitment; unsigned bits; };
struct SasChallenge { ShortCode random; };
struct SasOpening { ShortCode random; crypto::Key salt; };
std::string format_code(const ShortCode& code);
std::optional<ShortCode> parse_code(std::string_view text,unsigned bits);
class SasVerifier;
class AuthenticatedMessage {
  crypto::Bytes value;
  explicit AuthenticatedMessage(crypto::Bytes bytes):value(std::move(bytes)){}
  friend class SasVerifier;
public:
  bool matches(const crypto::Bytes& bytes)const{return value==bytes;}
};
class SasSender {
  SasParameters params;
  crypto::Bytes message;
  ShortCode random;
  crypto::Key salt{};
  std::optional<ShortCode> code;
  enum class State { Fresh,Committed,Done };
  State state=State::Fresh;
  void erase();
public:
  explicit SasSender(crypto::Bytes message,SasParameters parameters={});
  ~SasSender();
  SasSender(const SasSender&)=delete;
  SasSender& operator=(const SasSender&)=delete;
  SasCommitment begin();
  std::optional<SasOpening> open(const SasChallenge& challenge);
  // Available only after receiving a well-formed challenge and emitting opening.
  std::optional<ShortCode> display_code()const{return code;}
};
class SasVerifier {
  SasParameters params;
  std::optional<SasCommitment> incoming;
  ShortCode challenge;
  std::optional<ShortCode> expected;
  enum class State { Fresh,Challenged,AwaitingHuman,Done };
  State state=State::Fresh;
public:
  explicit SasVerifier(SasParameters parameters={});
  ~SasVerifier();
  SasVerifier(const SasVerifier&)=delete;
  SasVerifier& operator=(const SasVerifier&)=delete;
  std::optional<SasChallenge> receive(const SasCommitment& commitment);
  bool receive(const SasOpening& opening);
  // Caller must obtain this value from the intended sender through an authenticated
  // out-of-band channel. user_confirms is local input, never a network assertion.
  std::optional<AuthenticatedMessage> confirm(const ShortCode& authenticated_code,bool user_confirms);
};
}
