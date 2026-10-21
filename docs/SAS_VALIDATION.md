# Executed SAS authentication validation

Environment: Ubuntu 24.04.3 container; GCC 13.3.0; libsodium 1.0.18;
OpenSSL 3.0.13 (test-only reference SHA-512); CMake 4.4.4. No performance data.
Source PDF SHA-256:
925d8bb39cd08ddce4dbc1e1ebaf3e3b1cd54cecb8070554279af93e93d2e760.

Actual results in a correctness-only Release build:

```text
CTest: 4/4 passed
PASS: 4706 SAS commitment/challenge/opening/confirmation checks
PASS: 1152 Shamir/backup/restoration/lifecycle checks
```

Existing OPRF and initialization/recovery tests remain in CTest and passed.
SAS tests cover 200 honest instances over bit lengths 1,7,8,9,20,31,32,64,128,
256, including empty and binary messages. Each checks actual commitment values
against independently encoded OpenSSL SHA-512 input, XOR correctness, display/
parse round trip, evidence binding and repeated-step rejection. Additional
checks exercise leading-zero/uppercase hexadecimal representation, invalid
lengths/padding, tampered message/commitment/challenge/opening/salt/short code,
parameter disagreement and declined user confirmation. These tests establish
functional behavior, not empirical security advantage.

The lifecycle demo now executes the concrete three-message SAS exchange for
each guardian in both directions required by backup and restoration. It reports
initialization, 3-of-5 backup, restoration of the original device secret,
subsequent file-key recovery and client delivery all PASS. Its output explicitly
states that human OOB transfer is simulated. No ideal_sas_confirm remains in
library source, tests or examples.

sas_demo --auto-confirm-for-test passed with explicit test-mode labeling.
The default interactive path was also exercised through automated subprocess
stdin: the displayed sender code plus "yes" succeeded; "no" rejected. This
checks program input handling, not actual human recognition or remote OOB
channel authentication.

Debug ASan+UBSan CTest passed 4/4 with ASAN_OPTIONS=detect_leaks=0. Leak detection
remains disabled due to the previously observed /proc restriction. External
crypto libraries themselves were not rebuilt with sanitizers. No constant-time,
leak-freedom or complete formal proof compatibility claim is made.

Reproduction:

```sh
cmake -S . -B build-protocol -DCMAKE_BUILD_TYPE=Release -DPPKR_BUILD_BENCHMARKS=OFF
cmake --build build-protocol -j
ctest --test-dir build-protocol --output-on-failure
./build-protocol/sas_tests
./build-protocol/sas_demo
./build-protocol/lifecycle_demo
```

Remaining decisions: deployment short-code length, concrete authenticated OOB
channel/user identity checks, proof-level epsilon_auth accounting under the
chosen execution/channel semantics, and formal hash/commitment instantiation
compatibility. See SAS_INSTANTIATION.md for reference correspondence and exact
suite parameters. No change to the paper's security model is made by these tests.
