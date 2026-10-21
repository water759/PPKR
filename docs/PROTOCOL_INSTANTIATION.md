# Initialization and key recovery: implementation choices

## Scope and authoritative source

Implements the supplied PDF's Construction II.A, II.B, Figures 4 and 5.
Device D owns the password, device secret and both OPRF computations; HSM H
owns k_OPRF, verifies recovery signatures, and releases cf after acceptance.
C receives the final file key. This follows the uploaded PDF, not older protocol
summaries. The author-confirmed nonzero recovery blind correction is retained.

Implementation is a sequential, in-memory research prototype: typed messages
between separate Device/Hsm objects, with explicit Server::relay. No real HSM,
Bluetooth, networking, persistent database, QR image decoder or UI is included.
No backup/restoration implementation is introduced in this stage.

## Mathematical construction to functions

1. Device::begin_init samples k_D, computes rho_D, samples K_f and r_H,
   and emits (a_H, ID). Device record is not yet installed.
2. Hsm::begin_init samples PKE keys and k_OPRF, emits (b_H, pk_Enc, ID),
   and retains its secret keys as local temporary state.
3. Device::finish_init_crypto unblinds b_H; computes
   r_root=Hroot(root,rho_D,rho_H), k_kek=HKEK(kek,r_root),
   r_sig=Hroot(hsm-sig,r_root); deterministically generates signing keys;
   samples k_mk; encrypts cf=AE(k_mk,K_f), cmk=AE(k_kek,k_mk), and
   C=PKE(pk_Enc,(cmk,cf,pk_C)).
4. Hsm::accept_init decrypts C and installs exactly cmk,cf,pk_C,k_OPRF,
   counter=0 and current window time. Device::accept_init installs k_D and
   its own counter/time only on the initialization success response. The
   returned original K_f is the paper's local initialization output, not a
   transmitted secret or an extra public protocol message.
5. Device::begin_recovery applies the device window rule and increments
   ctr_D before computing the device OPRF and blinded HSM request.
6. Hsm::begin_recovery applies the HSM window check; returns b_H, cmk,
   fresh n_H and ID. It does not increment ctr_H at this step.
7. Device::authenticate reconstructs the root-derived signing key and signs
   exactly (RecAuth,a_H,b_H,ID,n_H). Hsm::authenticate verifies that tuple
   against stored pk_C. On failure increments ctr_H and returns Fail with
   no ciphertext; on success returns cf, without incrementing ctr_H.
8. Device::recover decrypts cmk then cf only after Succ, rejecting invalid AE
   ciphertexts. deliver_key encrypts K_f for C's scanned PKE public key;
   Client::receive decrypts it. No new signature or proof round is added.

DeviceInit, DeviceRecovery and the HSM pending maps are local temporary states,
not wire messages. Sequential per-ID calls are supported; active HSM calls
cannot be silently overwritten. Pending HSM state is consumed on completion.
Device completion records prevent repeating the completion/authentication steps
on that same local state. These are minimal execution/termination semantics,
not a concurrency/retry framework or additional security guarantee.

## Concrete cryptographic choices, for later proof compatibility review

* Existing OPRF suite is unchanged (see OPRF_INSTANTIATION.md).
* Lambda-bit bitstrings are instantiated as 32 bytes: K_f, k_mk, n_H,
  r_root, r_sig and k_kek. Group security remains approximately 128 bits.
* encode(fields) = concatenation of uint64_be(length(field)) || field.
  Raw byte strings are preserved, including empty values and embedded NULs.
* Hroot(fields) = first32(SHA512(encode("PPKR-v1/Hroot", encode(fields))));
  HKEK is identical except domain "PPKR-v1/HKEK". The labels "root", "kek"
  and "hsm-sig" are separate encoded fields, without terminating NULs.
  This is a concrete domain-separated hash instantiation of the paper's
  oracle/KDF interfaces, not an HKDF substitution or proof of oracle security.
* Sig.Gen(seed): libsodium Ed25519 crypto_sign_seed_keypair. Signatures are
  detached Ed25519 signatures (64 bytes); seed is exactly r_sig (32 bytes).
  The 32-byte pk is stored in the paper's pk_C field although D generates it.
* AE: XChaCha20-Poly1305-IETF, 32-byte key, uniformly sampled 24-byte nonce
  per encryption, 16-byte authentication tag. Encoding: nonce || ciphertext
  || tag. Associated data is empty, as the paper specifies no AE AD inputs.
  No password-based stretching or extra protocol binding is introduced.
* PKE: libsodium crypto_box_seal / seal_open: X25519-based sealed boxes,
  ephemeral sender key per encryption; 32-byte public/secret keys and 48-byte
  ciphertext overhead. No sender authentication is claimed. This supplies the
  paper's randomized PKE interface without adding a protocol exchange.
* Init plaintext is encode(cmk,cf,pk_C), strictly parsed as three fields with
  no trailing bytes and a 32-byte signing key. RecAuth signs encode of the five
  specified fields in order, including label RecAuth. No sid is introduced.

Concrete suites, hash mapping/oracle assumptions, output lengths, tuple coding
and group-input rejection still require reconciliation with the formal proof.
Tests prove functional properties on sampled/boundary inputs, not security
advantages. The module does not modify the paper's threat model.

## Time, channels and stop behavior

Policy(delta,L) is positive. The harness supplies monotonic logical seconds to
each party independently. Reset at now-start >= delta; reject at counter >= L.
Tests cover equality at the boundary and HSM failure-only counting. These
checks model the prescribed logic; no guaranteed hardware rate limit,
rollback resistance, counter synchronization or availability is claimed.

QR scanning is represented by passing Client::qr_public_key() to deliver_key.
The chosen public key is the one the device receives from the designated
client via the paper's QR step. Physical scanning/authentication is not measured.
No SAS-MA check is added to this QR delivery step; guardian SAS-MA belongs to
the later backup/restoration protocols and is outside this implementation.

std::nullopt/Fail represent abstract rejection/no local key. Malformed PKE/AE
ciphertexts are rejected; no error-recovery UI, retry policy, persistence,
concurrent sessions or transport security layer is designed here. Most secret
arrays and temporary contexts are ordinary C++ caller-owned memory. This is
not a production secret-memory lifecycle or side-channel audit; do not use
real passwords/keys in the example or expose local temporary states as messages.

## Build, run, and deferred measurements

```sh
cmake -S . -B build-protocol -DCMAKE_BUILD_TYPE=Release -DPPKR_BUILD_BENCHMARKS=OFF
cmake --build build-protocol -j
ctest --test-dir build-protocol --output-on-failure
./build-protocol/protocol_demo
```

Use -DCMAKE_PREFIX_PATH=/path/to/dependencies for a custom install. Existing
OPRF microbenchmarks remain available with PPKR_BUILD_BENCHMARKS=ON.
No formal latency, throughput or communication results are reported. Typed
messages do not yet define a complete serialized transport format; no total
wire-byte count is claimed. Full-protocol performance benchmarks and actual
CPU-affinity/governor runs are deferred until the measurement stage.
