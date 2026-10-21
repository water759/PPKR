# Recovery compute breakdown

This optional suite diagnoses the existing KeyRecoveryCpu workload. No protocol
or baseline cryptography is changed. The original full-workload results remain
the source for total recovery costs; these are separate component experiments.

| Case | Timed operation |
|---|---|
| RecoveryDeviceBeginCpu | Device record/window lookup, device PRF, fresh blinding, HSM request |
| RecoveryHsmBeginCpu | HSM record/window checks, OPRF evaluation, nonce, pending state/reply |
| RecoveryDeviceAuthenticateCpu | OPRF unblinding/finalization, KDF, regenerated signing keys, transcript signature |
| RecoveryHsmAuthenticateCpu | Pending lookup/removal, transcript verification, ciphertext reply |
| RecoveryDeviceDecryptCpu | Two AE decryptions and conversion to the recovered key |
| RecoveryClientKeygenCpu | Fresh client encryption keys (QR public-key preparation) |
| RecoveryDeliveryEncryptCpu | Device encrypts K to the scanned client public key |
| RecoveryDeliveryDecryptCpu | Client decrypts delivery and accepts K |
| DiagnosticDevicePrfCpu | Input encoding, device-record lookup and device PRF only |
| DiagnosticSigningKeygenCpu | Ed25519 key regeneration from an already available 32-byte seed only |

The two Diagnostic cases overlap the first eight cases. Do not add them to
component totals. Signing-key diagnostic excludes the KDF and signing operation;
the DeviceAuthenticate segment includes all of these operations.

All operations execute sequentially in software on the same CPU. Network,
QR hardware, human confirmation, physical HSM and concrete channel costs remain
excluded. These measurements are not per-device hardware latencies.

For each benchmark, a valid initialized file and the prefix needed by the target
method are prepared once before the iteration loop. Every iteration clones
that complete prepared state with timing paused, times only the selected method,
then completes the remaining recovery and compares both the device and client
outputs with the original K outside timing. This prevents counters, consumed
pending states or terminal flags from leaking between iterations. Random coins
inside the selected method remain freshly sampled. Prefix inputs and ciphertexts
are reused within each case: these are steady-input component microbenchmarks,
not fresh-session full protocol measurements. Fixture copies/destruction and
validation are excluded. Diagnostics validate against the actual device PRF or
a sign/verify check, respectively.

The first eight cases cover the real protocol method boundaries. Their means
need not sum exactly to the earlier total: local relay/message copies, harness
glue, cache state, reused prefix inputs and timer boundaries differ. Never derive
an unmeasured 'optimization speedup' just by subtracting component means. To
attribute the total difference rigorously, both schemes' full workloads and
comparable components would need matching instrumentation. This suite first
identifies the major costs of our construction, without altering the total or
claiming a complete decomposition of the Level-3 difference.

## Run

Reconfigure and rebuild a clean Release checkout after updating. Run CTest.
Use the same Release benchmark_DIR, performance governor and CPU as before.

```sh
python3 scripts/run_evaluation.py --build-dir build-eval --mode smoke \
  --suite breakdown --cpu 6 --random-interleaving
```

The new result directory contains breakdown.json, breakdown.log,
environment.json, and the existing protocol_sizes.csv. The CSV is unchanged
because this instrumentation does not change any protocol message or record.
The 'all' suite still means protocols + oprf for compatibility; breakdown is
selected explicitly. After inspecting smoke output, use --mode measurement.
Very short component timings can increase wall-clock calibration/setup costs;
no fixed completion time is promised.
