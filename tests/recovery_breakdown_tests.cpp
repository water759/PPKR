#include "evaluation/recovery_breakdown.hpp"
#include <iostream>
int main() {try {
  ppkr::oprf::initialize();
  for(int i=0;i<=static_cast<int>(ppkr::evaluation::RecoveryPart::SigningKeygenDiagnostic);++i) {
    const auto part=static_cast<ppkr::evaluation::RecoveryPart>(i);
    ppkr::evaluation::RecoveryBreakdown fixture;
    fixture.setup(part);
    for(int repeat=0;repeat<2;++repeat) {
      auto independent=fixture;independent.run(part);independent.validate(part);
    }
  }
  std::cout<<"PASS: all eight recovery segments complete to original K; both overlapping diagnostics validated\n";
  return 0;
} catch(const std::exception& e) {std::cerr<<e.what()<<'\n';return 1;}}
