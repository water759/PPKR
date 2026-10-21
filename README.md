# Device-Assisted Password-Protected Key Retrieval

C++17 research implementation accompanying **Device-Assisted Password-Protected
Key Retrieval with Compromise Containment**. The complete current implementation
is available on `main`; no development-branch checkout is required.

The code implements the cryptographic computations and sequential message flows
of initialization, key recovery, guardian-assisted device backup, and device
restoration. It is an in-memory software prototype for correctness testing and
subsequent performance evaluation, not a deployed key-recovery service.

## Protocol and source navigation

| Component | Source | Correctness tests |
|---|---|---|
| Device and HSM 2HashDH OPRF | [oprf.cpp](src/crypto/oprf.cpp) | [oprf_tests.cpp](tests/oprf_tests.cpp) |
| Initialization and key recovery | [core.cpp](src/protocol/core.cpp), [API](include/protocol/core.hpp) | [protocol_tests.cpp](tests/protocol_tests.cpp) |
| Guardian backup and device restoration | [backup.cpp](src/protocol/backup.cpp), [API](include/protocol/backup.hpp) | [backup_tests.cpp](tests/backup_tests.cpp) |
| Shamir sharing over the OPRF scalar field | [shamir.cpp](src/crypto/shamir.cpp) | [backup_tests.cpp](tests/backup_tests.cpp) |
| One-way SAS authentication (Vaudenay 2005, Fig. 5) | [sas.cpp](src/protocol/sas.cpp), [API](include/protocol/sas.hpp) | [sas_tests.cpp](tests/sas_tests.cpp) |
| Hash derivation, AE, PKE and signatures | [primitives.cpp](src/crypto/primitives.cpp) | [protocol_tests.cpp](tests/protocol_tests.cpp) |

## Build and reproduce correctness checks

Target environment: Ubuntu 24.04, C++17 compiler, CMake >=3.18,
libsodium >=1.0.18 development headers/library, and OpenSSL >=3.0 development
headers/library. Google Benchmark >=1.8.3 is required only when microbenchmarks
are enabled. Dependencies must be installed beforehand; CMake does not download
or build them automatically. Use `-DCMAKE_PREFIX_PATH=/path/to/dependencies`
if dependencies are installed in a custom prefix.

```sh
git clone https://github.com/water759/PPKR.git
cd PPKR
cmake -S . -B build-correctness \
  -DCMAKE_BUILD_TYPE=Release \
  -DPPKR_BUILD_BENCHMARKS=OFF
cmake --build build-correctness -j
ctest --test-dir build-correctness --output-on-failure
./build-correctness/lifecycle_demo
```

CTest contains five test groups: `oprf_correctness`, `protocol_correctness`,
`backup_correctness`, `sas_correctness`, and `evaluation_correctness`. The lifecycle demo initializes a
record, backs up the device secret with a 3-of-5 guardian configuration, restores
it into a new device using guardians 1,3,5, and uses that device to recover and
deliver the original file key to a client. It prints checks, not secret keys.

Additional demos:

```sh
./build-correctness/protocol_demo
./build-correctness/sas_demo
```

`sas_demo` requests manual entry of the displayed hexadecimal code and explicit
confirmation. Both roles run in one process; it demonstrates the input boundary,
not an authenticated connection between real remote peers. The lifecycle demo
executes the actual SAS commitment/challenge/opening steps, but simulates
out-of-band (OOB) code delivery and human confirmation. Its output states this.

## Implemented suites and abstraction boundaries

* Ristretto255 for the two domain-separated 2HashDH functions and its prime
  scalar field for Shamir sharing; nonzero OPRF keys/blinds.
* Domain-separated SHA-512 with specified encodings/output truncation;
  deterministic seeded Ed25519 signing keys; XChaCha20-Poly1305 AE; sealed-box PKE.
* Vaudenay 2005 Figure 5 one-way SAS message authentication with a hash-based
  commitment. The configurable default is 20 bits, displayed as five hexadecimal
  characters. This is an experimental default, not a deployment security claim.
* Typed messages, logical time, server relays and in-memory party records.
  No physical HSM, network service, persistence layer, Bluetooth transport or QR
  image decoder is implemented. Scanned client keys are supplied through an API.
* OOB peer recognition, short-code delivery, human confirmation and guardian
  owner recognition/approval remain explicit external inputs. The code does not
  establish these properties by displaying a code alone.

The implementation follows the supplied Construction. Concrete encoding,
Hash-to-Group, domain separation and cryptographic suite choices are documented
separately for review. Functional tests do not prove compatibility with every
security-proof assumption or replace a cryptographic audit. No VSS, share-origin
proof or extension of the paper's adversarial model is claimed.

## Validation status

Recorded container environment: Ubuntu 24.04.3, GCC 13.3.0, libsodium 1.0.18,
OpenSSL 3.0.13. Release correctness checks and the full lifecycle demo passed.
The current recorded executable check counts are 4,808 OPRF, 526 initialization/
recovery/component, 1,152 backup/restoration/lifecycle, and 4,706 SAS checks.
A further 80 evaluation workload/accounting checks passed.
Debug ASan/UBSan tests also passed with leak detection disabled because of the
container's process-information restriction; leak detection remains unverified.
These results are correctness evidence, not performance measurements.

| Module | Instantiation choices | Executed validation |
|---|---|---|
| OPRF | [OPRF_INSTANTIATION.md](docs/OPRF_INSTANTIATION.md) | [OPRF_VALIDATION.md](docs/OPRF_VALIDATION.md) |
| Initialization/recovery | [PROTOCOL_INSTANTIATION.md](docs/PROTOCOL_INSTANTIATION.md) | [PROTOCOL_VALIDATION.md](docs/PROTOCOL_VALIDATION.md) |
| Backup/restoration | [BACKUP_INSTANTIATION.md](docs/BACKUP_INSTANTIATION.md) | [BACKUP_VALIDATION.md](docs/BACKUP_VALIDATION.md) |
| SAS authentication | [SAS_INSTANTIATION.md](docs/SAS_INSTANTIATION.md) | [SAS_VALIDATION.md](docs/SAS_VALIDATION.md) |

Reports contain stage-specific history; the current SAS interface supersedes
the initial ideal-interface backup experiments.

## Performance evaluation status

Four protocol benchmarks, OPRF microbenchmarks, and a communication/storage
accounting profile are available. For a first local smoke run with Google
Benchmark installed:

```sh
cmake -S . -B build-benchmark -DCMAKE_BUILD_TYPE=Release \
  -DPPKR_BUILD_BENCHMARKS=ON
cmake --build build-benchmark -j
mkdir -p results
python3 scripts/run_evaluation.py --build-dir build-benchmark --mode smoke
```

See [EVALUATION.md](docs/EVALUATION.md) for timing boundaries, guardian/threshold
matrix, byte-count conventions, output artifacts and formal-run instructions.
Size values describe a specified application encoding and logical records, not
measured wire traffic or process memory. Formal hardware data collection and
analysis are still pending. No paper-ready timings, real HSM measurements or
human confirmation-time results are published.

## Level-3 comparison

The Faller et al. (2024) Figure 4 OPRF-PPKR baseline is implemented only for
initialization and recovery. See [docs/LEV3_BASELINE.md](docs/LEV3_BASELINE.md)
for the common-library instantiation, channel abstractions, byte profile,
four-case comparison commands and `scripts/compare_lev3.py` report.
