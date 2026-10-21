#include "evaluation/recovery_breakdown.hpp"
#include <stdexcept>
namespace ppkr::evaluation {
namespace {
void require(bool b) { if(!b)throw std::runtime_error("recovery breakdown correctness failure"); }
}
const char* name(RecoveryPart p) {
  switch(p) {
    case RecoveryPart::DeviceBegin:return "RecoveryDeviceBeginCpu";
    case RecoveryPart::HsmBegin:return "RecoveryHsmBeginCpu";
    case RecoveryPart::DeviceAuthenticate:return "RecoveryDeviceAuthenticateCpu";
    case RecoveryPart::HsmAuthenticate:return "RecoveryHsmAuthenticateCpu";
    case RecoveryPart::DeviceDecrypt:return "RecoveryDeviceDecryptCpu";
    case RecoveryPart::ClientKeygen:return "RecoveryClientKeygenCpu";
    case RecoveryPart::DeliveryEncrypt:return "RecoveryDeliveryEncryptCpu";
    case RecoveryPart::DeliveryDecrypt:return "RecoveryDeliveryDecryptCpu";
    case RecoveryPart::DevicePrfDiagnostic:return "DiagnosticDevicePrfCpu";
    case RecoveryPart::SigningKeygenDiagnostic:return "DiagnosticSigningKeygenCpu";
  }
  throw std::invalid_argument("unknown recovery part");
}
void RecoveryBreakdown::setup(RecoveryPart p) {
  auto init=device.begin_init(config.id,config.password);
  const auto reply=hsm.begin_init(init.second);
  const auto upload=device.finish_init_crypto(init.first,reply);
  expected=device.accept_init(init.first,hsm.accept_init(config.id,upload,0),0);
  require(expected.has_value());
  if(p==RecoveryPart::DevicePrfDiagnostic)return;
  if(p==RecoveryPart::SigningKeygenDiagnostic) {
    // Same 32-byte seed shape as crypto::derive; sample outside the timed region.
    diagnostic_seed=crypto::random_key();return;
  }
  for(int i=0;i<static_cast<int>(p);++i)run(static_cast<RecoveryPart>(i));
}
void RecoveryBreakdown::run(RecoveryPart p) {
  switch(p) {
    case RecoveryPart::DeviceBegin:
      begin=device.begin_recovery(config.id,config.password,1);require(begin.has_value());break;
    case RecoveryPart::HsmBegin:
      response=hsm.begin_recovery(begin->second,1);require(response.has_value());break;
    case RecoveryPart::DeviceAuthenticate:
      auth=device.authenticate(begin->first,*response);require(auth.has_value());break;
    case RecoveryPart::HsmAuthenticate:
      result=hsm.authenticate(config.id,*auth);require(result.success&&result.ciphertext.has_value());break;
    case RecoveryPart::DeviceDecrypt:
      recovered=device.recover(begin->first,result);require(recovered.has_value());break;
    case RecoveryPart::ClientKeygen:client.emplace();break;
    case RecoveryPart::DeliveryEncrypt:
      delivery=protocol::deliver_key(*recovered,client->qr_public_key());break;
    case RecoveryPart::DeliveryDecrypt:
      received=client->receive(delivery);require(received.has_value());break;
    case RecoveryPart::DevicePrfDiagnostic:
      diagnostic_prf=oprf::device_evaluate(oprf::encode_input(config.password,config.id),device.records.at(config.id).key);break;
    case RecoveryPart::SigningKeygenDiagnostic:
      diagnostic_signing=crypto::signing_from_seed(diagnostic_seed);break;
  }
}
void RecoveryBreakdown::validate(RecoveryPart p) {
  if(p==RecoveryPart::DevicePrfDiagnostic) {
    // Check the timed PRF against the real protocol's independently computed value.
    const auto actual=device.begin_recovery(config.id,config.password,1);
    require(actual.has_value()&&diagnostic_prf==actual->first.rho_d);return;
  }
  if(p==RecoveryPart::SigningKeygenDiagnostic) {
    require(diagnostic_signing.has_value());
    const auto msg=crypto::encode({"breakdown-validation"});
    require(crypto::verify(msg,crypto::sign(msg,*diagnostic_signing),diagnostic_signing->pk));return;
  }
  for(int i=static_cast<int>(p)+1;i<=static_cast<int>(RecoveryPart::DeliveryDecrypt);++i)
    run(static_cast<RecoveryPart>(i));
  require(recovered==expected&&received==expected);
}
}
