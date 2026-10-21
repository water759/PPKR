#pragma once
#include "evaluation/workload.hpp"
namespace ppkr::evaluation {
enum class RecoveryPart {
  DeviceBegin, HsmBegin, DeviceAuthenticate, HsmAuthenticate, DeviceDecrypt,
  ClientKeygen, DeliveryEncrypt, DeliveryDecrypt,
  DevicePrfDiagnostic, SigningKeygenDiagnostic
};
const char* name(RecoveryPart part);
// First eight parts follow the successful recovery's protocol method boundaries.
// Diagnostics overlap those parts and must never be added to their sum.
class RecoveryBreakdown {
  Config config;
  protocol::Device device;
  protocol::Hsm hsm;
  std::optional<crypto::Key> expected, recovered, received;
  std::optional<std::pair<protocol::DeviceRecovery,protocol::RecRequest>> begin;
  std::optional<protocol::RecResponse> response;
  std::optional<protocol::RecAuth> auth;
  protocol::RecResult result{false,std::nullopt};
  std::optional<protocol::Client> client;
  crypto::Bytes delivery;
  crypto::Key diagnostic_seed{};
  std::optional<crypto::Key> diagnostic_prf;
  std::optional<crypto::SigningKeys> diagnostic_signing;
public:
  void setup(RecoveryPart part);
  void run(RecoveryPart part);
  // Completes all remaining steps outside timing, then compares with original K.
  void validate(RecoveryPart part);
};
}
