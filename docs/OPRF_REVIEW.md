# OPRF construction-to-code review

Review scope: supplied paper Construction II.A/II.B and the original-device
argument in IV/Appendix A; code limited to the OPRF module. This is a local
implementation review, not a cryptographic proof or an external audit.

| Paper requirement | Implementation | Evidence/status |
|---|---|---|
| x = pw || ID | encode_input produces an injective length-prefixed pair | Empty, binary, split-boundary and 256-byte length tests; concrete encoding remains an explicit instantiation choice |
| k_D, k_OPRF in Z_q^* | random_scalar; canonical nonzero scalar checks | 0, q and above-q rejected; 1 and q-1 accepted; uniformity relies on libsodium, not frequency tests |
| a_D = H1(x)^k_D | device_evaluate | Separate OpenSSL SHA-512 transcript reference plus libsodium multiplication; fixed regression vector |
| rho_D = H2(x,a_D) | device_evaluate/finalize(Device) | Separate H2 tag and 32-byte output; fixed regression vector |
| a_H = H3(x)^r | hsm_blind | H3 is separated from H1; blind supplied by caller |
| b_H = a_H^k_OPRF | hsm_evaluate | Takes only request point and key, not password or ID; matches Construction's OPRF step |
| z = b_H^(1/r) | hsm_unblind | For 280 cases plus q-1 boundary, compare against test-only OpenSSL BN inversion and libsodium multiplication |
| rho_H = H4(x,z) | hsm_finalize | Equals unblinded HSM function across fresh blinds; separate H4 transcript reference |
| Nonzero r in recovery | random_scalar/scalar_check | Author confirmed missing star in II.B/Figure 5 is a typo |
| No added proof round | No DLEQ/VOPRF implementation | A modified valid response is accepted as a group element and changes the OPRF output; later protocol authentication is not implemented here |

## Limits of the completed checks

The functional equality (H3(x)^r)^k raised to r^-1 = H3(x)^k is
checked using a second scalar-inversion implementation. Both test paths still
use libsodium for point arithmetic. The OpenSSL BN path is test-only and has
no production constant-time claim. Hash reference paths use OpenSSL SHA-512;
production hashing uses libsodium SHA-512. Regression vectors freeze the
chosen suite, not interoperability with another OPRF standard.

The paper's proof treats H1/H2 and H3/H4 as public random oracles; domain
separation and passing tests do not prove that a concrete SHA-512/map suite
satisfies these assumptions. Retain this as an explicit assumption/review item.
The paper explicitly accounts for an identity-hash bad event. Our hash-to-group
path rejects identity rather than retrying. Identity replies are also rejected
at the module boundary; the proof's treatment of valid replies versus identity
replies must be reconciled before declaring exact malicious-transcript
compatibility. This review makes no change to the paper or protocol model.

The group size, output lengths, tuple serialization, secret-buffer ownership
and software-only HSM timing are documented in OPRF_INSTANTIATION.md.
This review covers only OPRF. Subsequent initialization/recovery work is described
in PROTOCOL_INSTANTIATION.md; subsequent backup/restoration work is described
in BACKUP_INSTANTIATION.md.

## Work possible before formal performance measurements

Completed: independent scalar-inverse reference, encoding boundary checks,
valid-response alteration checks, construction/API traceability, and a
correctness-only build check. Actual CPU affinity/governor experiments and
performance claims remain deferred. Full protocol implementation is a later
scope decision, not a dependency for running these OPRF tests.
