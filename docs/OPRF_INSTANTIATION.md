# OPRF instantiation v1 (experimental)

## Source and scope

Inspected repository main commit 986b8ee3f7969f6cd9827b1b34576cfa2e785da2.
It contained only placeholders, empty CMakeLists.txt/README, and .gitignore.
Existing nonempty files and placeholders are retained. Only the empty root
CMakeLists.txt was populated in the initial OPRF stage. The OPRF module itself
contains no full protocol, KDF, rate limiter or transport. For the subsequent
initialization/recovery module, see PROTOCOL_INSTANTIATION.md.

Source: supplied Device-Assisted Password-Protected Key Retrieval with Compromise
Containment PDF, Construction II.A/II.B, Figures 4/5, and device function in IV.
Device locally computes a_D=H1(x)^k_D, rho_D=H2(x,a_D).
HSM branch computes a_H=H3(x)^r, b_H=a_H^k_OPRF,
rho_H=H4(x,b_H^(1/r)). The device holds the input/blind; HSM only evaluates a point.
In additive Ristretto notation exponentiation is scalar multiplication.
Key generation is separate from evaluation and not included in evaluation timing.

## Explicit choices requiring proof compatibility review

* Group: libsodium Ristretto255, prime order
  q=2^252+27742317777372353535851937790883648493; 32-byte canonical points.
  Scalars are 32-byte canonical little endian. Sample uniformly using libsodium
  scalar_random and reject zero, matching Z_q^* (not all of Z_q).
* Input: x=field(pw)||field(ID), where field(v)=uint64_be(byte_length(v))||v.
  This instantiates the paper's pw||ID as an injective encoding of a tuple.
  Raw byte strings, including NUL/empty/non-ASCII, are accepted; no Unicode
  normalization or implicit terminator. Call encode_input exactly once.
* For H1/H3, compute SHA512(field(tag)||field(x)), then use libsodium's
  crypto_core_ristretto255_from_hash on all 64 bytes. Tags are ASCII
  PPKR-2HashDH-v1/H1 and PPKR-2HashDH-v1/H3 (no NUL).
  This is a libsodium map-based instantiation, not a claim of RFC 9497 compliance;
  do not substitute hash-to-scalar times a fixed generator (known discrete log).
* H2/H4: first 32 bytes of SHA512(field(tag)||field(x)||field(point)), with tags
  PPKR-2HashDH-v1/H2 and PPKR-2HashDH-v1/H4 respectively. Output is 256 bits.
  All four hash domains are distinct; no additional per-user/session domain.
* Reject noncanonical/zero scalars and noncanonical/identity points at module
  boundaries. A hash mapping to identity also raises an error, without retries.
  If the paper's random oracle maps to the entire group, excluding identity is
  a negligible exceptional event that must be explicitly reconciled with the
  formal model; tests cannot establish this or random-oracle security.
* Security parameter is fixed by this suite (roughly 128-bit group security,
  256-bit output); a 256-bit output does not imply 256-bit group security.
* No DLEQ proof, public evaluation key or verifiability step is added.

## Ownership and limits

Call initialize() before any OPRF operations. APIs accept already encoded x.
The supplied blind must be retained for that request; it is never resampled by
finalize. Scalar arrays are ordinary caller-owned buffers: callers must erase
keys, blinds, outputs and password buffers when no longer needed. The internal
inverse scalar and serialized hash transcript are erased. This is a performance
research module, not a complete secret-memory or side-channel-hardened product.
No real HSM or device, Bluetooth, network delay, SAS-MA, or hardware isolation is
measured. Host hsm_evaluate timing measures only software group computation.

Review against proof still needed: concrete hash/map assumptions and independent
oracle simulation, tuple encoding, chosen output length, group/security parameter,
identity rejection, and later Shamir field compatibility with this same q.
The supplied paper, not older conversation summaries, determines these formulas.

## Build and run (Ubuntu 24.04)

Dependencies: C++17 compiler, CMake >=3.18, OpenSSL >=3.0 development headers,
libsodium >=1.0.18, Google Benchmark >=1.8.3 (preinstalled, no automatic downloads).
Newer dependency versions are accepted; record actual versions for paper results.

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
ctest --test-dir build --output-on-failure
./build/oprf_tests
./build/oprf_bench --benchmark_list_tests
./build/oprf_bench --benchmark_repetitions=10 --benchmark_min_time=0.5s --benchmark_out=results/oprf.json --benchmark_out_format=json
```

For a custom dependency prefix append -DCMAKE_PREFIX_PATH=/path/to/prefix.
For correctness only append -DPPKR_BUILD_BENCHMARKS=OFF.
Select an actual performance-core CPU after checking the target machine topology:
`taskset -c <cpu> ./build/oprf_bench ...`. Do not infer P-core IDs from CPU count.
Record CPU model, governor, affinity, compiler/flags, dependency versions,
OS, power/thermal state and raw repetitions. Run formal timings on the user's
machine; cloud/container timings are smoke tests only.

Microbenchmarks cover scalar sampling, H1 map, device evaluation, HSM blind,
HSM evaluation, unblind (including inversion), finalize (unblind plus H4),
H2 output hash, and full HSM OPRF round trip. Stage benchmarks use fixed prepared
keys/blinds/requests outside the timed loop. RoundTrip samples a fresh blind
inside each iteration. No network, key generation, input encoding or device
branch is included in RoundTrip. Password lengths: 16 and 64 bytes, fixed ID.
Validation and public API allocation costs are included. Do not add medians
of component benchmarks to claim a measured end-to-end protocol latency.

Correctness tests use explicit checks (active in Release), 280 boundary/random
cases, OpenSSL SHA-512 reference transcript computation, direct libsodium group
algebra, repeated blinding invariance, key/input/domain sensitivity, and invalid
scalar/point rejection. The reference shares libsodium group primitives; this
is not an independent curve implementation or external interoperable vector.

## Author-confirmed notation correction

The author confirmed that II.B/Figure 5 printing recovery r'_H from Z_q
(without the star) is a typographical error. The intended distribution is
Z_q^*, excluding zero, consistent with II.A/Figure 4 and the inverse 1/r'_H.
The implementation already samples and accepts only nonzero canonical blinds;
no code change is needed. This notation question is resolved.
