# Device backup and restoration implementation

Authoritative source: supplied paper Construction II.C/II.D and Figures 6/7.
This stage completes the core sequential flows of the four protocols. It does
not implement a network service or a deployable SAS-MA protocol.

## Construction correspondence

* DeviceBackup obtains k_D from DeviceRecord, chooses a 32-byte backup version,
  sets x_j=j, samples Shamir coefficients in Z_q (zero allowed), and distributes
  one encrypted share per guardian. It never changes selected parameters to
  match a guardian's reply.
* BackupServer issues a fresh 32-byte rendezvous code and binds it to a logical
  device connection. Matching consumes the code and returns the two connection
  handles. Server::relay transfers typed messages without authenticating peers.
  The harness represents the user's out-of-band conveyance of the same code.
* Guardian::begin_backup requires explicit agreement, generates ephemeral PKE
  and acknowledgment keys plus a 32-byte nonce. Each endpoint constructs its
  own context from its own parameters, the rendezvous code and that nonce.
* Backup SAS sender is the guardian; verifier is D. Authenticated payload is
  (ShareRecipient,ctx_B,pk_Enc,j,pk_A,j). DeviceBackup::encrypt_share requires
  authenticated bytes matching its own constructed payload.
* Backup plaintext is (BackupShare,ctx_B,s_j), encrypted with the existing PKE
  primitive. Guardian checks tag/context/canonical field element before storing
  GuardianRecord. Its signature covers exactly (ShareStored,ctx_B,ciphertext).
  Device checks that exact ciphertext and context with authenticated pk_A,j.
* DeviceBackup::complete returns public metadata only after all n guardians
  have valid acknowledgments, even when t<n. The caller then sends it to
  BackupServer::store. No shares, polynomial or guardian private keys are part
  of the server's backup record.
* DeviceRestoration selects exactly t distinct guardian indices from metadata,
  then generates a fresh PKE pair. Each guardian checks ID/version/index against
  its own record, samples a fresh nonce, and returns t,n,x_j,nonce. Replacement
  validates these against its selected metadata before constructing ctx_R.
* Recovery SAS sender is D'; verifier is the guardian. Payload is
  (RecoveryRecipient,ctx_R,pk_Enc). Guardian::release_share independently checks
  authenticated bytes against its own context, recognizes_owner and approves.
  Only then encrypts (RecoveryShare,ctx_R,s_j). Stored guardian shares remain
  available for later restoration.
* Replacement checks PKE decryption, tag/context, canonical share and distinct
  nonzero coordinates, and waits for all t shares. It reconstructs k_D using
  the paper's interpolation coefficients product_{l!=j}(-x_l)/(x_j-x_l), then
  installs DeviceRecord with counter 0 and supplied current time. The restored
  record can be passed directly to the existing key recovery implementation.

## Field and encoding choices

Shamir uses exactly the Ristretto scalar order
q=2^252+27742317777372353535851937790883648493. Field encodings are canonical
32-byte little endian values; zero shares and zero coefficients are allowed.
OPRF keys/blinds continue to use Z_q^*, as previously documented. Arithmetic
uses libsodium scalar add/subtract/multiply/invert, not point arithmetic.
The low-level reconstruct helper interpolates the supplied nonempty set;
it does not know t. The protocol wrapper enforces collection of t shares.
No claim that fewer shares cause an intrinsic interpolation error is made.

All compound values use the existing uint64_be-length-prefixed encoder.
ctx=(ID,version,t,n,j,x_j,code,nonce), with t,n,j represented by exactly 8-byte
big endian values, x_j by its canonical 32-byte field encoding, and version,
code,nonce by 32 bytes. Context is encoded as one nested field in SAS, share
and acknowledgment payloads. No sid or extra authentication round is added.
Fresh Guardian acknowledgment signing seeds are uniform 32-byte values.
Encryption/signatures reuse the previous sealed-box/Ed25519 suite.

Counts use host size_t and indices use uint64_t. On the supported 64-bit Ubuntu
target, representable counts are automatically below q; tests use small sets.
No arbitrary-precision participant counts or large-scale allocation claim.

## SAS-MA is an explicit abstract dependency

The PDF specifies SAS-MA as a primitive, without a concrete commit/exchange/
short-code algorithm in these Construction steps. ideal_sas_confirm is a
correctness-testing functionality: it creates AuthenticatedMessage only when
the sender/verifier payloads match exactly and user_confirms is true. Each
receiving party then checks the evidence against its independently constructed
payload. Guardian owner recognition and recovery approval are separate explicit
inputs, not inferred from a rendezvous code or an encryption public key.

In the recovery harness, the sender payload is handed to this ideal functionality
and Guardian::release_share checks it against the guardian's actual local
payload. That models primitive-level context authentication; it is not a
concrete network SAS exchange, human recognition system, or short-code security
implementation. A public hash truncated to digits is deliberately not presented
as SAS-MA. No false-acceptance probability or epsilon_auth measurement is claimed.
The ideal interface cannot be used as a deployed authentication mechanism.

The randomly generated rendezvous token likewise represents connection setup,
not a human-friendly displayed code format or endpoint authentication.

## Erasure, scope and limits

Shamir coefficient storage is wiped after shares are computed (earlier than the
paper's final backup cleanup); private share copies are wiped when cleared or
destroyed. Guardian ephemeral PKE/signing secret keys are wiped when its backup
step completes or pending state is destroyed. The guardian's stored share
persists. Replacement share copies and ephemeral decryption key are wiped at
successful restoration, structural rejection or destruction. Decrypted share
plaintext buffers are wiped after parsing. These are concrete local cleanups,
not a general guarantee about allocator copies, process memory snapshots or all
secret lifetime handling in the pre-existing modules.

No share-origin proof, verifiable secret sharing, share correction or extra
signature is added to recovery. As in the paper, recovery PKE alone does not
authenticate a guardian to D'. The paper's ShareRoute restriction remains an
external adversarial-model condition, not an implemented server integrity
mechanism. Structural rejection tests do not extend the security claims to
attacker-substituted valid shares or add retry/availability guarantees.

Persistence, actual QR/SAS displays, Bluetooth and network transport remain
abstract. No physical HSM/device measurement, SAS user study, formal proof audit,
full wire serialization or large-guardian performance result is claimed.

## Run without performance testing

```sh
cmake -S . -B build-protocol -DCMAKE_BUILD_TYPE=Release -DPPKR_BUILD_BENCHMARKS=OFF
cmake --build build-protocol -j
ctest --test-dir build-protocol --output-on-failure
./build-protocol/backup_tests
./build-protocol/lifecycle_demo
```

The lifecycle demo performs 3-of-5 backup, restores from guardians 1,3,5 into a
new Device object, then recovers and delivers the original file key to C.
