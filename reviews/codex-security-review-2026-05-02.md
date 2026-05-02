# Codex Security Review - 2026-05-02

## Scope

This review focused on bugs and crypto vulnerabilities that may not be exposed by the current happy-path tests, with emphasis on:

- `providers/arm_asm`
- `providers/psa_mbedtls`
- high-level EC, KDF, and secure-buffer wrappers

The OpenSSL provider was intentionally left out because it is still work in progress.

## Executive Summary

The highest-risk issues are in the ARM ASM EC implementation. Before the ARM backend is used for real secret-bearing workloads, it should reject invalid EC inputs, avoid secret-dependent table access in ECDSA signing, and align signature/public-key validation with PSA behavior.

The PSA/MbedTLS provider is generally leaning on PSA for validation, which is the right direction. The main PSA-adjacent concerns found here are provider behavior mismatches and high-level wrapper validation gaps.

## Findings

### 1. [P1] ARM ECDH accepts unvalidated peer points

Location: `providers/arm_asm/arm_asm_backend.hpp:565-575`

`raw_key_agreement` checks only SEC1 prefix and byte length before constructing `Q = (x, y, 1)` and multiplying it by the private scalar. It does not reject:

- coordinates outside the field
- points not satisfying the curve equation
- non-canonical P-521 encodings with high bits set
- invalid public keys before scalar multiplication

This can create invalid-curve style exposure in the ARM ECDH path and diverges from PSA, where imported ECC public keys are validated by the provider.

Proposal:

- Add curve-specific public-key parsing helpers for P-256, P-384, and P-521.
- Reject non-canonical coordinates before constructing field elements.
- Check `y^2 == x^3 - 3x + b mod p`.
- Reject identity/invalid encodings.
- Use these helpers in ECDH and ECDSA verify paths, and ideally at EC public-key import time.
- Add tests with malformed SEC1 points, off-curve points, all-zero points, coordinates equal to `p`, and P-521 high-bit encodings.

### 2. [P1] ARM fixed-base scalar multiplication leaks secret nibbles

Locations:

- `providers/arm_asm/p256_point.hpp:317-320`
- `providers/arm_asm/p384_point.hpp:272-276`
- `providers/arm_asm/p521_point.hpp:299-303`

The fixed-base scalar multiplication routines branch on secret nibbles and index precomputed `G` tables with secret-dependent values. This path is used for public-key derivation and ECDSA signing nonce multiplication. In ECDSA, leakage of enough nonce bits can recover the private signing key.

Proposal:

- Replace secret-dependent `if (nibble != 0)` and `G_table[nibble - 1]` with constant-time table selection.
- Always execute the same number of additions per window, selecting either the table point or a neutral/identity representation without secret-dependent branches.
- Audit the resulting generated code on target compilers, since constant-time source patterns can still be optimized poorly.
- Add a code-level regression test or helper review checklist for fixed-base multiplication so future curves do not reintroduce secret-dependent table access.

### 3. [P2] ARM ECDSA accepts non-canonical `r` and `s`

Location: `providers/arm_asm/ecdsa.hpp:218-220`

ECDSA verification parses `r` and `s` with scalar helpers that reduce modulo `n` instead of checking `1 <= r,s < n`. As a result, an encoded value like `n + x` may be accepted as `x`. P-521 parsing also masks high bits rather than rejecting them.

This is signature malleability and also a provider mismatch: PSA should reject non-canonical signatures.

Proposal:

- Add scalar decoding helpers that validate canonical scalar encodings without reduction.
- Use canonical scalar parsing for signature `r` and `s`.
- Keep reduction helpers only for hash/scalar arithmetic where reduction is intended.
- Add tests for `r = 0`, `s = 0`, `r = n`, `s = n`, `r = n + 1`, `s = n + 1`, all-ones encodings, and P-521 high-bit encodings.

### 4. [P2] ARM EC key import is length-only validation

Location: `providers/arm_asm/ec_key_store.hpp:59-69`

The EC key store accepts key bytes based only on `key_len <= ec_max_key_bytes`. It stores curve/kind metadata from the caller without checking curve-specific length, public-key prefix, private scalar range, or public-key curve membership.

Later callers perform some length checks, but malformed keys can still be imported and retained in the process-global store. This makes the ARM backend easier to misuse directly and leaves behavior inconsistent with PSA.

Proposal:

- Validate EC keys at import time according to `curve` and `kind`.
- Private scalars should be canonical and satisfy `1 <= d < n`.
- Public keys should be uncompressed SEC1 points with exact expected length and on-curve coordinates.
- Reject `EcCurveId::None`, `EcKeyKind::None`, mismatched lengths, and non-canonical P-521 encodings.
- Add direct provider tests for invalid imports.

### 5. [P2] `SecureBuffer` move assignment can release secrets without zeroizing

Location: `safe-crypto-lib/secure_buffer.hpp:40-41`

`SecureBuffer` defaults its move assignment operator. If a destination `SecureBuffer` already owns secret bytes, assigning a different buffer can allow the underlying `std::vector` move assignment to release or replace the existing allocation without first calling `secure_zero` on the old contents.

Proposal:

- Implement custom move constructor and move assignment.
- In move assignment, wipe existing `data_` before taking ownership from the source.
- Consider making moved-from buffers empty after transfer.
- Add focused tests using an instrumented allocator if practical, or at least unit tests that exercise move assignment and resizing behavior.

## Additional Hardening Notes

### ARM AEAD nonce length

Location: `providers/arm_asm/arm_asm_backend.hpp:378-405`

The ARM AEAD encrypt/decrypt functions accept a `nonce_len` parameter but ignore it. The AES-GCM and ChaCha20-Poly1305 primitives then consume 12 nonce bytes unconditionally. High-level callers currently pass fixed 12-byte IVs, but direct provider callers or future APIs could pass shorter buffers.

Proposal: require `nonce_len == 12` before calling the primitive.

### ARM key stores are process-global and unsynchronized

Locations:

- `providers/arm_asm/key_store.hpp:34-76`
- `providers/arm_asm/ec_key_store.hpp:53-104`
- `providers/arm_asm/rsa.hpp:69-120`

The ARM symmetric, EC, and RSA stores all mutate static slot arrays without locking or atomics. Concurrent imports, reads, or destroys can race.

Proposal: either document and enforce that the ARM backend is single-threaded, or protect key stores with synchronization and use handles that cannot be destroyed while an operation is reading them.

### KDF runtime validation

Location: `safe-crypto-lib/kdf.hpp:23-127`

`derive_key_impl` and `expand_key_impl` rely on `SAFE_CRYPTO_PRE(output_length > 0)`, but contracts are a no-op on clang and most current compilers. `derive_key_impl` also multiplies `output_length * 2` and `ikm_ref.size() * bits_per_byte` without overflow checks.

Proposal:

- Add runtime validation for `output_length == 0`.
- Check multiplication overflow before `output_length * 2` and bit-size conversion.
- Add tests for zero output length and near-`SIZE_MAX` lengths.

### PSA and ARM ECDSA hash selection differ

Locations:

- `providers/psa_mbedtls/psa_mbedtls_backend.hpp:279`
- `providers/arm_asm/arm_asm_backend.hpp:462-547`

PSA hardcodes `PSA_ALG_ECDSA(PSA_ALG_SHA_384)` for every curve. ARM uses SHA-256 for P-256, SHA-384 for P-384, and SHA-512 for P-521. Existing cross-provider ECDSA coverage appears centered on P-384, where the two happen to match.

Proposal:

- Decide whether ECDSA hash algorithm is curve-specific or fixed by the library API.
- If curve-specific, expose provider algorithms per curve.
- Add P-256 and P-521 cross-provider ECDSA tests.

## Suggested Remediation Order

1. Disable or clearly mark ARM ASM EC signing/ECDH as experimental until EC validation and scalar multiplication leakage are addressed.
2. Add canonical EC public-key and scalar parsing helpers.
3. Fix ARM ECDH and ECDSA verify to use validated public points and canonical signatures.
4. Replace secret-dependent fixed-base table access with constant-time selection.
5. Add malformed-input and cross-provider tests for EC public keys, ECDH, and ECDSA.
6. Fix `SecureBuffer` move assignment.
7. Add runtime validation in KDF wrappers and AEAD nonce-length checks.
