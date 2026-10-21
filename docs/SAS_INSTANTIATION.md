# Concrete one-way SAS message authentication

## Reference and scope

Serge Vaudenay, "Secure Communications over Insecure Channels Based on Short
Authenticated Strings," CRYPTO 2005, LNCS 3621, pp. 309-326. Source inspected:
the supplied Vau05a(1).pdf, Section 4 Figure 5, Section 2.2 Example 2, Theorem 5
and Section 5 Lemma 6. The PDF is not copied into the repository.

Implements the three insecure-channel moves of Figure 5 with separate
SasSender and SasVerifier state machines. Authenticated out-of-band delivery
of the short code and recognition of the intended sender are still caller/user
responsibilities, exactly as an external authenticated channel in the paper.
This is a cryptographic protocol implementation, not a voice/Bluetooth/GUI
transport implementation or a human-factors security validation.

## Reference steps and APIs

1. SasSender::begin samples independent uniform k-bit R_A and 256-bit salt e,
   commits to R_A tagged by the application message m, emits (m,c,k).
2. SasVerifier::receive(commitment) checks the fixed local k agrees, retains
   the received message and commitment, samples uniform k-bit R_B and emits it.
3. SasSender::open accepts one canonical challenge, emits d=(R_A,e) and makes
   SAS=R_A XOR received_R_B available through display_code(). SasVerifier
   verifies the opening against its actual received m,c, then computes its
   expected code from opened_R_A XOR locally generated_R_B.
4. The sender communicates its displayed SAS via the authenticated OOB channel.
   SasVerifier::confirm checks that supplied code and explicit user confirmation.
   Only it can construct AuthenticatedMessage for the actual received m. The
   application additionally checks that authenticated bytes match the exact
   context/public-key payload that it expected.

A short code is unavailable before sender opening; no authentication evidence
can be obtained before a valid opening plus confirmation. Repeated commitment,
challenge, opening or confirmation steps are refused as appropriate to local
state. A failed opening or confirmation cannot later be retried on that state.
The API checks concrete length, unused bits and local parameter agreement.
No sid, new DH exchange, additional signature round or long-term SAS key is
introduced. The existing PPKR protocol flow and share-release policy are retained.

## Instantiation choices requiring security compatibility review

The reference's Example 2 samples e and uses c=H(m||R_A||e), d=R_A||e.
Our unambiguous representation is:

```
c = first32(SHA512(encode("PPKR-SAS-v1/commit", uint64_be(k), m, R_A, e)))
d = (R_A,e)
```

encode is the existing uint64_be-length-prefixed tuple encoder. The public
suite label and fixed k instantiate a tagged, injectively encoded hash input;
they are not extra protocol rounds. c and e are 32 bytes each. No simple
collision-resistance claim is substituted for the reference's extractable/
equivocable commitment assumption. Using SHA-512 truncated to 256 bits is a
concrete random-oracle instantiation assumption, not a standard-model proof.
Independent OpenSSL SHA-512 computation checks this encoding against actual
commitments in tests; production hashing uses libsodium SHA-512.

k is configurable from 1 to 256 bits; both endpoints must preconfigure the
same k. The default k=20 is an illustrative experimental parameter, not an
approved deployment security level. Test-only k=1 is included to exercise
bit boundaries and is not a recommended operational parameter.
R_A/R_B are ceil(k/8) random bytes with unused high bits of the first byte
masked to zero, hence uniform over exactly 2^k values. Noncanonical encodings
are rejected. XOR operates on that fixed-width encoding. The display format
is exactly ceil(k/4) hexadecimal characters with leading zeros preserved;
nonexistent high bits must remain zero. Parsing accepts upper/lowercase hex,
but no whitespace, omitted digits or decimal-modulus mapping. At k=20 this
is five hexadecimal characters, not five decimal digits or a six-digit OTP.
Changing that display to decimal requires a fresh encoding decision.

Theorem 5 bounds a one-shot attack by 2^-k + epsilon_commit (subject to the
commitment complexity assumption). Example 2 includes hash-query-dependent
hiding and collision events. Tests do not measure those advantages. Lemma 6's
general multi-instance transformation incurs Q_A*Q_B, not just the number of
successful user confirmations. No generic q_auth*2^-k bound is inferred here,
and the PPKR paper's abstract epsilon_auth parameter is not silently replaced
by such a formula. Relating its sequential admitted executions and channel
semantics to a concrete per-check bound remains a proof-integration task.
No human miscomparison probability is measured or assumed away by code.

## Backup/restoration integration

The ideal_sas_confirm function and its friend access were removed from the
library. AuthenticatedMessage can only be constructed by SasVerifier after
valid commitment opening and explicit OOB confirmation.

Backup: guardian is sender for (ShareRecipient,ctx_B,pk_Enc,j,pk_A,j); device
is verifier. Existing DeviceBackup::encrypt_share checks evidence against
its own originally selected parameters and returned public keys.

Restoration: replacement D' is sender for (RecoveryRecipient,ctx_R,pk_Enc);
guardian is verifier. Existing Guardian::release_share checks evidence against
its own local-record-derived context, recognizes_owner and approves inputs.
These last two local decisions remain separate from comparing the short code.
This direction does not authenticate the guardian to D'. No recovery share
origin proof, VSS or change to ShareRoute is added.

The automated tests and lifecycle_demo explicitly execute all three SAS moves,
then simulate delivery of the actual sender-generated code over the OOB channel
and set user confirmation. The application still checks its independent context.
This is no longer an ideal whole-message comparison in place of SAS, but neither
is automatic confirmation a deployed authenticated transport or human study.

## Demo and reproducibility

```
cmake -S . -B build-protocol -DCMAKE_BUILD_TYPE=Release -DPPKR_BUILD_BENCHMARKS=OFF
cmake --build build-protocol -j
ctest --test-dir build-protocol --output-on-failure
./build-protocol/sas_demo
./build-protocol/lifecycle_demo
```

sas_demo runs both roles locally, displays Alice's code, requests Bob's input
and the explicit word "yes" to confirm identity/OOB delivery. It illustrates
the manual boundary, not real remote peer authentication. The explicit flag
--auto-confirm-for-test simulates only OOB transfer and human approval and
labels that mode in its output. It is not the default for sas_demo.

No latency or human-comparison timing is reported. Future benchmarks must
separate ordinary-channel messages, cryptographic work and OOB/human time.
Typed SAS messages are not yet a versioned transport serialization format.
Sender random coins and local salt are wiped after opening or object destruction;
opening copies are public once transmitted, not long-term secret credentials.
