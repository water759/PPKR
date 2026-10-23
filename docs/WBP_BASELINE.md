# WBP baseline

## Source

Davies et al., *Security Analysis of the WhatsApp End-to-End Encrypted Backup
Protocol*, CRYPTO 2023, ePrint 2023/843. This reimplementation follows Section
3.5, Figures 4 and 5 of the user-supplied WBP.pdf, not current OPAQUE RFC code.
It is experimental software, not WhatsApp code or a production OPAQUE library.

The initialization flow samples K and the client's static DH key; performs the
password-only OPRF; derives export/mask/auth keys; XOR-masks the DH scalar;
MAC-authenticates the credential tuple; encrypts K under the export key;
PKE-encrypts the envelope, transcript hash and credentials to the HSM's static
public key; checks the decrypted transcript; and stores the record with ctr=10.
Recovery runs the password OPRF, authenticates/unmasks credentials, computes
all three DH secrets independently on each side, derives two MAC keys and a
session key, verifies both confirmation MACs, resets ctr, session-encrypts the
stored envelope, and decrypts both layers at the client. T_S is an explicit
reply field; client checks never read the HSM's pending secrets.

ID_C is mapped to a fresh aid by S. The HSM record is addressed by aid, not
ID_C. Reinitialization retires the old aid; failed attempts decrement ctr;
starting at ctr=0 deletes the record. These are sequential successful-workload
benchmarks, not availability/concurrency evaluations.

## Concrete primitive choices

Uses the existing Ristretto255 2HashDH and SHA-512-derived 32-byte OPRF output.
The WBP OPRF input is the password alone, as in the source; we do not append ID.
3DH uses Ristretto255 as well: shared secrets in order are ephemeral/ephemeral,
client-ephemeral/HSM-static and client-static/HSM-ephemeral. DH does not reuse
OPRF secrets or substitute a single DH for the three operations.
PKE is the existing X25519 sealed box; AE is existing XChaCha20-Poly1305.
Ed25519 instantiates the HSM signature where enabled. HMAC-SHA256 is the MAC;
KDF1 and KDF2 instantiate HKDF-SHA256. KDF1 extracts with n_e as salt and the
OPRF output as IKM, expands label WBP/KDF1 to 96 bytes, splitting into export,
mask, auth. KDF2 extracts the raw concatenated three 32-byte DH values with
H3(pre) as salt, expands WBP/KDF2 to 96 bytes, splitting into server MAC,
client MAC, session key. H3 is SHA-512 truncated to 32 bytes. Credential MAC,
transcript hashes and preambles use the repository's length-prefixed tuple
encoding. Client confirmation hashes pre followed by T_S. The source treats
these building blocks abstractly; these explicit choices are not a byte-exact
implementation of WhatsApp or a claim to its UC security theorem. No extra
password stretching step is inserted. Static global HSM PKE/DH/signing key
creation is fixture setup outside timing, as keys are pre-established in the
paper. Per-user OPRF keys and client static keys are generated inside Init.

## Two measurement boundaries

* WbpInitializationCpu / WbpKeyRecoveryCpu: HSM attestation is an ideal channel
  property; no HSM signature generation/verification is timed and no signature
  payload is charged. This is the boundary used by the existing Level-3 and
  device-assisted baseline's abstract authenticated channels. Mandatory WBP
  credential and 3DH MAC checks are ALWAYS executed. Primary comparison uses
  these cases and must explicitly say attestation costs are excluded for all.
* WbpAttestedInitializationCpu / WbpAttestedKeyRecoveryCpu: includes exactly the
  HSM signature and verification specified by Figures 4/5, plus transmitted
  signature bytes. Initialization signs the encoded (b1,n1); recovery signs b2.
  A zero-length optional signature field in the primary encoding remains as an
  eight-byte prefix; the attested variant adds 64 bytes on each of two hops.
  This sensitivity result is not directly comparable to the other schemes
  as a fully attested benchmark, since those schemes' concrete attestation has
  not been implemented. Never mix the two WBP modes or hide the difference.

Every iteration has fresh fixture state and protocol randomness. Prerequisite
initialization, validation and fixture destruction are paused, matching the
existing full workloads. Prefixes are NOT reused as in the separate breakdown
suite. Post-run checks compare the actual recovered K with original K.
The source's authenticated C-S/TLS S-H transport and sec_store/sec_retr operations
are idealized. No outsourced-storage encryption, DB/network I/O, HSM hardware,
QR capture or human authentication delay is measured. Tombstones and account
mapping are logical in-memory state. Retained tombstone history is not a fixed
per-current-user record and is excluded from the current-record storage figure.

## Communication and storage

protocol_sizes appends wbp_initialization, wbp_key_recovery and their two
wbp_attested counterparts. Previous rows and the original column order remain;
server_account_mapping_bytes is appended as a new column (zero for old rows).
There are now 34 CSV rows and 34 protocol benchmark cases.

For WBP, C-S and S-H messages have different aid headers, so every actual hop
is encoded separately. These bytes/messages occupy the CSV's legacy
server_control_bytes/server_control_messages fields (general one-hop bucket),
with relayed_* zero. This does NOT mean WBP has no relayed messages. Total
ordinary_hop_bytes/messages remain the appropriate comparison fields.
Init has seven one-way hops (the last result goes H-to-S only); Rec has eight.
App tags and lengths are a documented encoding profile, not wire traffic.

The logical HSM user record includes aid, OPRF key, envelope, client DH public
key, masked scalar, envelope nonce/tag, and counter. Shared static HSM keys are
excluded from per-user sizes. S's separate ID_C-to-aid record is reported in
server_account_mapping_bytes, not hidden in HSM storage. Test-reference K,
volatile client/HSM state, and outsourced record ciphertext overhead are excluded.
Both Init and Rec output 32 bytes to C. WBP has no social/device-backup rows;
absence must not be presented as zero-cost backup.

## Build and compare

Use the user's existing Release benchmark_DIR. Run all correctness tests, then:

```sh
python3 scripts/run_evaluation.py --build-dir build-eval --mode smoke \
  --suite protocols --cpu 6 --random-interleaving \
  --filter '^(Wbp|Lev3)?(Initialization|KeyRecovery)Cpu$'
```

This selects six cases: WBP, Level-3, and our scheme, Init/Rec each. It does not
repeat the guardian matrix or OPRF suite. CPU 6 is specific to the user's already
selected machine; choose an allowed CPU on other machines. After inspecting
smoke output, use --mode measurement. To measure the signature sensitivity,
filter '^WbpAttested(Initialization|KeyRecovery)Cpu$' separately.

Generate a three-scheme comparison from the SAME result directory:

```sh
python3 scripts/compare_wbp.py results/measurement-TIMESTAMP
```

The report contains no assumed performance ranking. Do not combine the WBP
result with old two-scheme timings to claim a same-run comparison. No final
paper data from the user's machine is included in this commit.
