# WBP implementation validation

Local validation only; no final paper performance dataset.

- Release build: 8/8 CTest groups passed, including the unchanged existing tests.
- WBP group: 99 checks covering RFC 5869 HKDF vector, independent OpenSSL HMAC,
  Ristretto basepoint/DH checks, correct recovery in both attestation modes,
  wrong passwords, envelope-tag/transcript/server-MAC/signature modification,
  client-MAC rejection, consumed and cross-session proof replay, ciphertext
  modification, client-static-public-key substitution, reinitialization,
  counter exhaustion/deletion, binary passwords and deterministic size accounting.
- ASan/UBSan WBP group: 99 checks passed. Leak detection was disabled for the
  container restriction; external libsodium/OpenSSL are not instrumented.
- Targeted smoke run: 8 Init/Rec cases (WBP core, WBP attested, Level-3, ours),
  three repetitions each; no benchmark errors. Report script parsed the same-run
  six-case primary comparison successfully. These timings are not paper data.
- Size output: 34 rows; the hop-byte identity passed for every row. Concrete HSM
  signatures add 128 encoded payload bytes per successful phase over the core
  mode (64 bytes on each of two relay hops). Source masks, MACs and all three
  DH values are computed in both modes.

See WBP_BASELINE.md for exact measurement boundaries and remaining abstractions.
