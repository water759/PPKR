# Executed backup/restoration validation

Environment: Ubuntu 24.04.3 container, GCC 13.3.0, libsodium 1.0.18,
OpenSSL 3.0.13 (existing test reference), CMake 4.4.4. No performance run.

## Executed tests

* Shamir split/reconstruct for every t in 1..n, n=1..6, using zero, 17 and a
  random secret, across every subset of exactly t shares.
* Independently specified polynomial 17+3X+5X^2; modular wraparound polynomial
  (q-1)+X at (1,0),(2,1); zero/repeated/invalid coordinates and invalid shares.
* Complete backup/restoration lifecycle for 1-of-1, 1-of-3, 2-of-3, 3-of-5 and
  5-of-5, with every threshold-sized subset in those configurations. Each new
  device recovers the original device secret, uses it to recover the original
  file key from the HSM, and delivers that key to a fresh client.
* All n valid acknowledgments required before metadata is returned; modified
  and duplicate acknowledgments reject. Rendezvous tokens are one-use and are
  tested as connection handles, not as authentication credentials.
* Backup SAS mismatch for version/ID, encryption key, acknowledgment key and
  nonce. Negative user confirmation and mismatching authenticated bytes reject.
* Recovery share release rejects substituted recipient/context, missing owner
  recognition and missing approval. Guardian stored shares remain available
  over repeated successful restorations with different subsets.
* Missing version records, invalid metadata/subsets, repeated coordinate, fewer
  than t shares, altered ciphertext, wrong tag/context/version/nonce, malformed
  plaintext and out-of-field share rejection. No incomplete device record is
  installed when restoration cannot complete.

Actual direct output:

```text
PASS: 4808 checks; 280 randomized/boundary cases
PASS: 526 initialization/recovery/primitive checks
PASS: 1152 Shamir/backup/restoration/lifecycle checks
```

Release CTest passed 3/3. A separate correctness-only Release configuration
(PPKR_BUILD_BENCHMARKS=OFF) also passed 3/3 and the complete lifecycle demo.
The demo reports initialization, 3-of-5 backup, restoration, device-secret
comparison, key recovery and client delivery all PASS, and explicitly labels
SAS-MA as an ideal correctness interface.

Debug ASan+UBSan CTest passed 3/3 with ASAN_OPTIONS=detect_leaks=0. Leak checking
remains unverified because of the previously documented /proc restriction;
external crypto libraries are not themselves sanitizer-instrumented.
One intermediate Release CTest run could not start protocol_tests because its
workspace executable bit was absent. Restoring the local executable permission
and rerunning yielded 3/3 passed; no source workaround was introduced.

These are functional/structural checks with an ideal SAS-MA dependency. They do
not demonstrate a deployed short-code protocol, proof-game security, validity
of substituted shares outside ShareRoute, real HSM isolation, arbitrary
concurrency or measured latency/throughput. Instantiation and abstraction
choices are detailed in BACKUP_INSTANTIATION.md.


## Subsequent concrete SAS implementation

The above describes the initial backup-stage run. Current tests and the lifecycle
demo now execute the concrete Vaudenay 2005 Figure 5 SAS protocol. Only OOB delivery
and human approval are simulated. See SAS_VALIDATION.md and SAS_INSTANTIATION.md;
the initial ideal-interface description is historical, not the current library API.
