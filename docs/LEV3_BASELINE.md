# Level-3 baseline: Faller et al. (2024)

## Source and scope

This is our software reimplementation of Section 4.3, Figure 4 of
*Password-Protected Key Retrieval with(out) HSM Protection*, not author code.
Only OPRF-PPKR (Level-3) is implemented. Section 5 Tables 3/4 are analytical
operation counts, not an experimentally measured latency dataset.

Initialization samples K, runs a client/HSM OPRF with a fresh per-user HSM key,
generates a random signature key pair, AE-encrypts (K, sk_C) under the OPRF
output, and PKE-encrypts (ssid, pk_C, c) to a fresh HSM public key. The HSM
checks the decrypted ssid and stores (ID_C, pk_C, c, k_OPRF, ctr=10).
Recovery decrements ctr, evaluates the OPRF, decrypts (K, sk_C), signs exactly
(a, ID_C, ssid, b, c), verifies at the HSM, and resets ctr to 10 on success.
An attempt beginning at ctr=0 deletes the record. Backup/restoration are not
provided by this baseline. They must not be presented as zero-cost equivalents.

## Common instantiation and measurement boundary

Both implementations use the existing libsodium components: Ristretto255
2HashDH OPRF with SHA-512-derived 32-byte output; Ed25519 signatures;
X25519 sealed-box PKE; XChaCha20-Poly1305 AE. This is a common-library
instantiation of the Figure 4 protocol, not the Schnorr/DHIES/AES-GCM
instantiation used for the paper's analytical Table 3. In particular, do not
claim measured values validate Table 3's exact exponentiation counts or claim
that sharing primitives establishes all of the source's UC theorem assumptions.

The full 64-byte Ed25519 secret key is wrapped together with the 32-byte K,
with the same explicit uint64 length prefixes used in our implementation.
The baseline does not derive the signing key from the password, add a device,
add a client-delivery encryption, or change the baseline counter policy.

Benchmarks Lev3InitializationCpu and Lev3KeyRecoveryCpu follow the same
pause/setup/run/validate/destroy timing convention as the existing workloads.
Fresh 32-byte ssid values are external session inputs sampled during fixture
setup, not timed. Recovery setup initializes a file and then chooses a new
recovery ssid. Required cryptographic encodings are timed; optional size-only
encodings are disabled. Only successful honest executions are benchmarked;
wrong passwords, modified ciphertexts/verification keys and exhaustion are
covered by correctness checks.

All roles run sequentially in one process on one CPU. Costs are software CPU
work, not network or real HSM latency. HSM-attested channels and client-to-server
authenticated channels are assumed: their signatures, verification, channel
setup and framing are excluded. This follows the exclusion of HSM attestation
signatures in the source's Section 5, and the channel abstraction of the current
prototype. Any deployment comparison must account for concrete channel costs
on both sides; this benchmark alone cannot support claims about those costs.

Our KeyRecoveryCpu includes fresh client encryption keys and encrypted D-to-C
key delivery. Baseline Rec ends with K at C and needs no such extra delivery.
Report this boundary explicitly: both workloads end with K at the client, but
the device-based construction needs an extra delivery step. Do not remove it
merely to make overhead smaller. Device backup/restoration are separate rows.
The current baseline does NOT provide per-role timings or measured networking.

## Byte and storage profile

protocol_sizes now adds lev3_initialization and lev3_key_recovery rows to the
existing CSV. Same uint64-length-prefix encoding and ID/password lengths.
ssid fields are included in the baseline, as specified by Figure 4. Our protocol
has a different message syntax; this is a comparison of the documented encoding
profiles, not a claim about minimum theoretical wire size.

Three messages in each baseline phase traverse C-S-H (six hops). The final
result travels H-S only (one hop), exactly as Figure 4, and is recorded in the
CSV's server_control fields. Its status encoding is InitRes/RecRes + ssid + one result byte.
Attestation signatures, TLS, transport headers and connection setup are excluded.
Message hops are not interaction rounds. Use the source's 3-round convention
for its Init/Rec, and separately derive our protocol's dependencies under the
same convention before comparing round counts.

Storage counts only (ID_C, pk_C, c, k_OPRF, ctr) with HSMRecord framing;
no HSM ephemeral PKE keys, sessions, client test-reference values, C++ container
allocations or device record are counted. client_output_key_bytes is 32 for
both baseline stages because Figure 4 outputs K to C during Init and Rec.
Persistent stored-file costs are comparable; output-key placement differs in
the current device-based initialization and must be identified separately.

## Run only the directly comparable cases

After committing changes, reconfigure a clean Release checkout using the
Release Google Benchmark installed on the measurement machine:

```sh
cmake -S . -B build-eval -DCMAKE_BUILD_TYPE=Release \
  -DPPKR_BUILD_BENCHMARKS=ON \
  -Dbenchmark_DIR="$HOME/PPKR-deps/benchmark-release/lib/cmake/benchmark"
cmake --build build-eval -j
ctest --test-dir build-eval --output-on-failure
python3 scripts/run_evaluation.py --build-dir build-eval --mode smoke \
  --suite protocols --cpu 6 --random-interleaving --filter '^(Lev3)?(Initialization|KeyRecovery)Cpu$'
```

CPU 6 refers to the previously selected CPU on the user's measurement machine,
not a portable CPU choice. Retain power mode and other environment settings.
After inspecting smoke output, replace --mode smoke with --mode measurement.
There are four cases; no need to repeat the guardian matrix or OPRF suite.
The runner records the random-interleaving flag in the benchmark command; it
interleaves repetitions across the four cases to reduce fixed-order bias.

Summarize the four cases and their size rows from the SAME run:

```sh
python3 scripts/compare_lev3.py results/measurement-TIMESTAMP
```

The report includes mean CPU time, sample standard deviation, CV, microsecond
delta and percentage change, plus encoded-hop-byte, separate QR public-key,
HSM-record, device-record and combined HSM/device storage comparisons.
Negative change means a decrease. Human approval and network latency are not
included. Do not preselect an outcome such as 'small overhead'; use measured
values. A low CV within one invocation is not evidence of cross-run stability.
