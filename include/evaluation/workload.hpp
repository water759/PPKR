#pragma once
#include "protocol/backup.hpp"
namespace ppkr::evaluation {
enum class Stage { Initialization,KeyRecovery,DeviceBackup,DeviceRestoration };
const char* name(Stage stage);
struct Config { std::size_t n=5,t=3;std::string id="alice@example.org",password="0123456789abcdef"; };
struct Traffic {
  std::uint64_t relayed_bytes=0,relayed_messages=0,server_bytes=0,server_messages=0,direct_bytes=0,direct_messages=0;
  std::uint64_t sas_bits=0,sas_checks=0,rendezvous_bits=0,qr_bytes=0;
  std::uint64_t ordinary_bytes()const{return 2*relayed_bytes+server_bytes+direct_bytes;}
};
struct Storage {std::uint64_t device=0,hsm=0,guardians=0,metadata=0,client_output=0;};
// Fixed profile of logical records/messages for size accounting, not a transport codec.
class Workload {
  Config config;
  protocol::Device device,restored;
  protocol::Hsm hsm;
  protocol::BackupServer server;
  std::vector<protocol::Guardian> guardians;
  std::optional<crypto::Key> original,recovered,client_key;
  std::optional<protocol::BackupMetadata> backup_metadata;
  Traffic* traffic=nullptr;
  void relayed(const crypto::Bytes& bytes);
  void control(const crypto::Bytes& bytes);
  crypto::Key rendezvous();
  protocol::AuthenticatedMessage sas(const crypto::Bytes& sender,const crypto::Bytes& expected);
  void initialize();void recover();void backup();void restore();
public:
  explicit Workload(Config config={});
  // Prerequisites are separate so benchmarks can exclude setup.
  void setup(Stage stage);
  void run(Stage stage,Traffic* accounting=nullptr);
  void validate(Stage stage)const;
  Storage storage(Stage stage)const;
};
std::vector<std::pair<std::size_t,std::size_t>> scenarios();
std::string build_revision();
}
