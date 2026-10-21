#pragma once
#include "evaluation/workload.hpp"
namespace ppkr::evaluation {
// Honest software execution of Faller et al. (2024), Figure 4 only.
// Attested/authenticated channels are idealized, not cryptographic operations here.
class Lev3Workload {
  Config config;
  crypto::Key session=crypto::random_key(); // externally supplied ssid, excluded from timing
  std::optional<crypto::Key> original,recovered;
public:
  struct Record {
    crypto::Key pk;
    crypto::Bytes ciphertext;
    oprf::Scalar oprf_key;
    std::uint64_t counter=10;
  };
  std::optional<Record> record;
  explicit Lev3Workload(Config c={}):config(std::move(c)){}
  void setup(Stage stage);
  void run(Stage stage,Traffic* traffic=nullptr);
  void validate(Stage stage)const;
  Storage storage(Stage stage)const;
  void initialize(Traffic* traffic=nullptr);
  // Wrong-password attempts decrement ctr; an attempt at ctr=0 deletes the file.
  bool recover(std::string_view password,Traffic* traffic=nullptr);
};
}
