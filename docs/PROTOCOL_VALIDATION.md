# Executed initialization/recovery validation

Environment: Ubuntu 24.04.3 container; GCC 13.3.0; OpenSSL 3.0.13;
libsodium 1.0.18; CMake 4.4.4. Actual performance on user hardware is unmeasured.

## Checks exercised

* Twenty independent initialization fixtures and repeated recoveries, including
  correct password -> wrong password -> correct password, with a fresh blind
  and nonce for each invocation.
* Stored pk_C equals the deterministically derived signing public key; both
  encryption layers decrypt to the initialized file key.
* Device/HSM records are installed only after prescribed completion steps.
* Client decryption yields exactly the original file key; wrong client and
  modified delivery ciphertext reject.
* Empty, non-ASCII and embedded-NUL identifiers; embedded-NUL passwords.
* Missing records, duplicate initialization, failed PKE decryption and malformed
  initialization tuple rejection; failed initialization installs no records.
* Modified HSM reply point, nonce, signing key and signature fail authentication;
  modified cmk passes HSM authentication but fails device AE decryption (it is
  not a signed RecAuth field); modified cf fails the second AE decryption.
* Each of a_H, b_H, ID and n_H is separately verified as part of RecAuth.
  Completed HSM calls cannot be authenticated twice; an old signature fails
  against a fresh recovery nonce; completed device state cannot yield keys twice.
* Correct device attempt counting, HSM failure-only counting, window blocking,
  and reset exactly at delta; no timing sleeps or wall-clock benchmarks.
* AE/PKE round trips including empty plaintext, wrong keys, truncation and tag
  alteration; deterministic seeded Ed25519 signing/key generation; fixed root,
  KEK and signing-public-key regression vectors using a Python hashlib reference.

## Results

Release CTest: 2/2 passed (oprf_correctness and protocol_correctness).
Direct executables:

```text
PASS: 4808 checks; 280 randomized/boundary cases
PASS: 526 initialization/recovery/primitive checks
Initialization: PASS
Key recovery: PASS
Client delivery matches original key: PASS
```

A correctness-only Release configuration (PPKR_BUILD_BENCHMARKS=OFF) also
passed both tests and the demo. Debug ASan+UBSan CTest passed 2/2 with
ASAN_OPTIONS=detect_leaks=0. LeakSanitizer remains disabled because of the
previously observed /proc restriction; third-party crypto libraries themselves
were not rebuilt with sanitizers. No formal leak-freedom or constant-time claim.

Re-run commands (repository root):

```sh
cmake -S . -B build-protocol -DCMAKE_BUILD_TYPE=Release -DPPKR_BUILD_BENCHMARKS=OFF
cmake --build build-protocol -j
ctest --test-dir build-protocol --output-on-failure
./build-protocol/oprf_tests
./build-protocol/protocol_tests
./build-protocol/protocol_demo
```

No formal performance measurements were run in this stage. No backup,
guardian SAS-MA or device-restoration end-to-end test exists yet. Tests do not
establish security under the paper's adversarial game. Remaining suite/proof
compatibility questions are listed in PROTOCOL_INSTANTIATION.md.
