# Local evaluation workflow and measurement definitions

The suite includes four device-assisted protocol workloads plus the Level-3
Init/Rec baseline; see [LEV3_BASELINE.md](LEV3_BASELINE.md) for comparison scope.
It does not add/change protocol cryptography. Run a smoke test first; publish
measurements only after controlling and documenting the target environment.

## Build and first local check

Use a clean checkout of the current main revision. Google Benchmark >=1.8.3
must already be installed, alongside the dependencies listed in README.md.

```sh
cmake -S . -B build-eval -DCMAKE_BUILD_TYPE=Release -DPPKR_BUILD_BENCHMARKS=ON
cmake --build build-eval -j
ctest --test-dir build-eval --output-on-failure
python3 scripts/run_evaluation.py --build-dir build-eval --mode smoke
```

The script creates a new directory under results/ on every invocation, never
replaces previous results, and prints the resulting path. Defaults for smoke:
3 repetitions per case and 0.05s minimum benchmark time. Calibration, excluded
setup and cleanup still consume elapsed time, so these parameters are not a
promise about the command's total duration. Smoke output is not final data.

Artifacts:

| File | Meaning |
|---|---|
| protocols.json | Google Benchmark per-repetition data plus aggregates |
| protocols.log | Benchmark stdout/stderr, including warnings |
| protocol_sizes.csv | Application encoding and logical-record size profile, 30 rows |
| environment.json | Mode, revision, binary hashes, compiler/build flags, library version, affinity, CPU/governor/power/load snapshots and commands |

The script checks that benchmarks actually matched the filter and did not
report an error. Failed runs are marked failed in the manifest. Measurements
require a clean checkout, matching configured build revision and Release mode;
reconfigure/rebuild after updating source. OPRF benchmarks remain separately
available via --suite oprf or --suite all. No governors or global machine
settings are changed by the script.

## What is timed

All four protocol workloads run sequentially in one process. Google Benchmark's
CPU time is the primary compute-cost value; its JSON also records real time.
These are software role-computation costs, including the current implementation's
allocations, logical state operations, local relay copies and protocol checks.
They are not distributed end-to-end latency or physical HSM latency.

| Benchmark | Timed operations | Excluded prerequisite setup |
|---|---|---|
| InitializationCpu | D/H key generation, OPRFs, derivation, signatures' key generation, two AE layers, PKE upload, state establishment | Empty fixture allocation |
| KeyRecoveryCpu | Correct-password OPRFs, signature authentication, AE decryption, fresh client PKE keys and encrypted delivery | Initialization |
| DeviceBackupCpu/n:N/t:T | Shamir sharing, all N guardian connections, key generation, concrete SAS, PKE shares, signed acknowledgments and metadata publication | Initialization |
| DeviceRestorationCpu/n:N/t:T | Metadata retrieval, new recipient keys, T guardian connections, concrete SAS, encrypted shares, interpolation and replacement state installation | Initialization and backup |

Restoration does not include subsequent file-key recovery. If the paper needs
that combined cost, measure a separate combined workload rather than relabeling
restoration alone. Backup always waits for all N acknowledgments, not only T.

Every iteration has fresh fixture state and fresh protocol randomness. Setup,
post-run independent validation and fixture destruction occur with timing paused.
Protocol-local temporary cleanup remains part of the timed protocol method.
Record-retirement cleanup after the workload is excluded. Traffic serialization
and size reporting are disabled during timed runs. No printing or file I/O
occurs in the timed interval. Required protocol checks stay enabled.

Real network delay, QR capture/rendering and human/OOB transfer/recognition
are excluded. The three-message SAS cryptographic steps are executed and timed;
only code transfer and human approval are simulated. The current suite uses
20-bit SAS and 256-bit rendezvous tokens. Guardian operations are sequential;
no parallel-user throughput or multi-machine speedup is claimed.

Fixed ID: alice@example.org (17 bytes), password: 0123456789abcdef (16 bytes).
The current workload is the honest successful case; wrong-password denial and
rate-limit behavior are correctness-tested, not represented as successful timing.

Matrix: (n,t) = (1,1), (3,1), (3,2), (3,3), (5,1), (5,3), (5,5),
(10,1), (10,6), (10,10), (20,1), (20,11), (20,20).
There are 30 benchmark cases: two base protocols, two Level-3 baselines,
13 backup and 13 restoration cases. Restoration selects indices 1..t. The threshold/guardian matrix can be
extended in evaluation::scenarios without modifying protocol logic.

## Communication accounting profile

protocol_sizes executes the actual crypto flows separately, then computes sizes
under a specified canonical application-payload profile. This is exact byte
accounting for that profile, not measured packets and not a complete deployed
transport serializer. Payload tags/outer framing are instantiation choices for
accounting; they do not add authentication or alter the protocol's inner crypto.

Encoding uses the existing uint64_be length prefixes. Numeric n,t,j,counters
and logical times occupy eight big endian bytes as fields; result flags use one
byte. Ciphertexts, signatures and keys retain their actual computed lengths.
The explicit profile is implemented next to every accounting event in
src/evaluation/workload.cpp. SAS messages include the actual Figure 5 m,c,
challenge and opening; the message/key context retransmitted inside SAS is
counted, rather than omitted as "already sent".

* relayed_payload_bytes_once counts each end-to-end logical message once.
* ordinary_hop_bytes = 2*relayed_payload_bytes_once + server_control_bytes +
  direct_bytes. Each relayed message has two logical party hops through S,
  even when H is physically co-located with S. This is not automatically two
  Internet transmissions. ordinary_hop_messages follows the same convention.
* Server-control messages include rendezvous request, code reply and guardian
  code submission (three per connection); backup metadata publication or
  retrieval query/response are counted separately. Connection/TLS setup,
  rendezvous matching notifications not specified in Construction, and retry
  traffic are excluded. Connection handles are harness objects, not payloads.
* Encrypted file-key delivery is one direct D-to-C logical message. The scanned
  client public key is separately reported in qr_public_key_bytes, not added to
  the ordinary-channel byte total or confused with QR image size.
* sas_oob_bits reports exactly k bits per SAS check. rendezvous_oob_bits reports
  the current 256-bit code handed out-of-band to each guardian. Neither includes
  spoken words, hexadecimal character storage, user confirmation or UI framing.

There is no TCP/IP, Bluetooth, HTTP, TLS, database or filesystem overhead claim.
To report real wire bytes later, implement/measure the actual chosen transport.
Never label these values as measured network bandwidth.

## Storage accounting profile

Values are encoded logical persistent records after each stage, not sizeof(C++)
objects, heap/RSS, database files or peak memory. They include the record label,
ID and framing for each paper record. DeviceRecord contains key/counter/time;
HSMRecord contains the two ciphertexts, signing public key, OPRF key and
counter/time; GuardianRecord contains its parameters, one coordinate and one
share; BackupRecord contains public parameters and all index/coordinate pairs.
The repeated C++ share.x member is not counted twice in the logical GuardianRecord.
client_output_key_bytes reports the delivered key only, not an extra protocol
record. Original test-reference secrets and ephemeral keys are not counted.

For restoration, device_record_bytes describes one replacement record, not
retention of the lost device plus a replacement. HSM/guardian/metadata fields
report total retained system records, not newly added bytes for that stage.
Do not sum different stage rows as if every row created another independent
copy. Guardian mean size excludes device/server storage.

## Formal local measurement, after inspecting the smoke result

Plug in power, pause competing heavy tasks and let temperature/load settle.
Inspect the actual hybrid CPU topology before choosing a logical CPU; do not
assume CPU 0 or any fixed index is a P-core on the i9-14900HX.

```sh
lscpu -e=CPU,CORE,SOCKET,ONLINE,MAXMHZ
python3 scripts/run_evaluation.py --build-dir build-eval --mode measurement --cpu <chosen_cpu>
```

--cpu is optional; when provided it pins the runner and child processes and
records affinity. The placeholder must be replaced by a real allowed CPU number.
The script does not ensure a P-core was selected, control SMT contention, fix
frequency/turbo or attest thermal stability. Record any external power-mode
choices. Formal defaults: 10 repetitions, 0.5s minimum per benchmark case.
Raw repetitions and aggregate statistics are retained. Do not present only the
fastest run. Repeat when unexplained variance or environment changes justify it.

No paper-ready performance dataset is included in this repository. Reproduction
of current code is distinct from final proof/instantiation compatibility review.
