# ARM ASM Provider Plan

## Target

ARMv8-A / AArch64 — Apple Silicon (M-series) and compatible ARM64 hardware.
Built and tested on macOS with Apple clang or Homebrew LLVM.

## Requirements

- Implements the same `CryptoProvider` concept interface as `safe-crypto-lib`.
- Only implements primitives in intrinsic/ASM where there is a measurable benefit:
  - Functions that benefit from ARM Crypto Extension instructions (AES, SHA2, SHA3, PMULL).
  - Functions that benefit from NEON SIMD (e.g. wide XOR chains, polynomial multiply for GCM).
  - Functionality without a meaningful hardware-accelerated path is implemented in C++26
    (e.g. key management, KDF orchestration, ECDH/ECDSA, RSA).
- All intrinsic/ASM code must be constant-time and side-channel resistant — no secret-dependent
  branches, no secret-dependent memory access patterns.
- Intrinsic code should be instruction-ordering aware (load–compute–store sequencing,
  avoiding unnecessary pipeline stalls).
- Optimize for throughput on Apple Silicon's wide out-of-order pipeline while preserving
  the constant-time constraint.
- Code must be readable and maintainable: one logical operation per block, named
  intermediate variables, concise inline comments where the ISA mapping is non-obvious.

## Available ARM Crypto Extensions (verified on this machine)

| Extension | Intrinsic prefix | Use |
|---|---|---|
| `__ARM_FEATURE_AES` | `vaese`, `vaesd`, `vaesmc`, `vaesimc` | AES round function |
| `__ARM_FEATURE_AES` (PMULL) | `vmull_p64` | GCM GHASH field multiply |
| `__ARM_FEATURE_SHA2` | `vsha256h`, `vsha256h2`, `vsha256su0`, `vsha256su1` | SHA-256 compression |
| `__ARM_FEATURE_SHA2` | `vsha512h`, `vsha512h2`, `vsha512su0`, `vsha512su1` | SHA-512 compression |
| `__ARM_FEATURE_SHA3` | `veor3`, `vbcaxq`, `vrax1q`, `vxarq` | SHA-3/Keccak permutation |
| NEON | `vld1q`, `vst1q`, `veorq`, `vaddq`, etc. | Wide loads, XOR, arithmetic |

## Implementation Phases

### Phase 1 — SHA-256 (foundation)

SHA-256 is the most-used primitive (HMAC, HKDF, ECDSA). A correct, constant-time
hardware-accelerated SHA-256 unblocks everything downstream.

**Approach:**
- 4-way unrolled message schedule using `vsha256su0q_u32` / `vsha256su1q_u32`.
- Compression using `vsha256hq_u32` / `vsha256h2q_u32` with two state register pairs.
- Process one 64-byte block per call; caller loops over message chunks.
- Initial hash constants and round constants stored in `constexpr` arrays.

**Files:**
- `arm_asm/sha256.hpp` — `sha256_compress_block(state, block)` — single block step.
- `arm_asm/sha256.cpp` — message padding, multi-block loop, output serialisation.

**Deliverable:** `hash_compute` returns correct SHA-256 for arbitrary-length input.
Tests: compare against `RealPsaBackend` output on a range of inputs (empty, 1 byte,
55 bytes, 56 bytes, 64 bytes, 1 MiB).

---

### Phase 2 — SHA-512 / SHA-384

Same structure as Phase 1 using the SHA-512 intrinsics.
SHA-384 is a truncated SHA-512 with different initial constants.

**Files:**
- `arm_asm/sha512.hpp` — `sha512_compress_block`.
- `arm_asm/sha512.cpp` — padding, loop, output.

**Deliverable:** `hash_compute` correct for SHA-384 and SHA-512.

---

### Phase 3 — HMAC (SHA-256 and SHA-384)

HMAC is two SHA calls (inner and outer hash) with key padding.
No new ISA primitives needed once Phases 1 and 2 are done.

**Files:**
- `arm_asm/hmac.hpp` — `hmac_compute(key, message, sha_variant) -> digest`.

**Deliverable:** `mac_compute` and `mac_verify` for HMAC-SHA-256 and HMAC-SHA-384.
Tests: RFC 4231 HMAC test vectors.

---

### Phase 4 — AES-256-GCM

The highest-throughput operation and the one where ARM AES instructions deliver
the largest speedup over pure C++.

**Sub-tasks:**
1. **AES-256 key expansion** — `aes256_key_expand(key) -> round_keys[15]` using
   `vaeseq_u8` + `vaesmcq_u8` round-key derivation. Constant-time by construction
   (no branches on key material).
2. **AES-256-CTR encrypt/decrypt** — 4-block-at-a-time CTR using 4 NEON registers,
   interleaving `vaeseq_u8`/`vaesmcq_u8` with counter increment.
3. **GHASH** — field multiplication in GF(2¹²⁸) using `vmull_p64` (PMULL), 4-step
   Karatsuba reduction, constant-time by construction.
4. **GCM combine** — AAD processing, ciphertext authentication tag.

**Files:**
- `arm_asm/aes256.hpp` — key schedule, CTR block encrypt.
- `arm_asm/ghash.hpp` — GHASH accumulator.
- `arm_asm/aes256_gcm.hpp` — encrypt/decrypt combining CTR + GHASH.

**Deliverable:** `aead_encrypt` and `aead_decrypt` for AES-256-GCM.
Tests: NIST CAVP AES-GCM test vectors; cross-check against `RealPsaBackend`.

---

### Phase 5 — SHA-3 (Keccak)

SHA3-256/384/512 use the Keccak-f[1600] permutation. ARM SHA3 extensions
(`veor3q_u64`, `vbcaxq_u64`, `vrax1q_u64`, `vxarq_u64`) accelerate the χ, θ,
and ρ/π steps.

**Files:**
- `arm_asm/keccak.hpp` — `keccak_f1600(state[25])`.
- `arm_asm/sha3.hpp` — padding (domain suffix, rate), sponge absorb/squeeze.

**Deliverable:** `hash_compute` for SHA3-256, SHA3-384, SHA3-512.
Tests: NIST SHA-3 Known Answer Tests.

---

### Phase 6 — ChaCha20-Poly1305

ChaCha20 is highly NEON-friendly (quarter-round maps to 4-wide NEON add/XOR/rotate).
Poly1305 MAC uses 128-bit arithmetic that maps well to NEON registers.

**Files:**
- `arm_asm/chacha20.hpp` — `chacha20_block(key, counter, nonce) -> keystream[64]`;
  4-block-at-a-time variant for throughput.
- `arm_asm/poly1305.hpp` — accumulator, clamp, final reduction.
- `arm_asm/chacha20_poly1305.hpp` — AEAD combine.

**Deliverable:** `aead_encrypt` and `aead_decrypt` for ChaCha20-Poly1305.
Tests: RFC 8439 test vectors; cross-check against `RealPsaBackend`.

---

### Phase 7 — HKDF (SHA-384)

HKDF-Extract and HKDF-Expand are pure HMAC compositions. Once Phase 3 is done,
this phase wires them into `key_derivation_setup` / `key_derivation_input_key` /
`key_derivation_output_bytes` using the internal HMAC from Phase 3.

**Files:**
- `arm_asm/hkdf.hpp` — extract and expand.

**Deliverable:** `key_derivation_*` functions for HKDF and HKDF-Expand (SHA-384).
Tests: RFC 5869 test vectors.

---

## Operations delegated to PSA/MbedTLS (C++ glue, no custom ASM)

These involve complex math (modular arithmetic, lattice operations, primality testing)
where no ARM Crypto Extension provides a meaningful primitive:

- ECDSA sign/verify (P-256/384/521)
- ECDH key agreement
- RSA-OAEP / RSA-PSS
- Key import / export / generation
- Random generation (delegates to OS CSPRNG)

The `ArmAsmBackend` will hold a private `RealPsaBackend` instance and forward these
operations directly.

---

## Key management strategy

`ArmAsmBackend` owns an internal PSA key store for operations it delegates to
`RealPsaBackend`. For operations it implements natively (SHA, AES-GCM, ChaCha20,
HMAC, HKDF) it holds key material directly in `SecureBuffer` and never imports
into PSA. The `KeyId` type will be a discriminated handle that distinguishes
"native key" from "PSA key."

---

## Testing strategy

- Each phase adds golden-vector tests comparing `ArmAsmBackend` output against
  published test vectors (NIST, RFC).
- A second test layer runs the existing `psa_error_tests.hpp` suite against
  `ArmAsmBackend` to verify the `CryptoProvider` contract is satisfied.
- All tests run on the same binary as the existing suite — no separate test target.

---

## File layout (target state)

```
providers/arm_asm/
  arm_asm_backend.hpp       # ArmAsmBackend — satisfies CryptoProvider
  arm-asm-plan.md           # This file
  aes256.hpp                # AES-256 key schedule + CTR
  aes256_gcm.hpp            # AES-256-GCM AEAD
  chacha20.hpp              # ChaCha20 stream
  chacha20_poly1305.hpp     # ChaCha20-Poly1305 AEAD
  ghash.hpp                 # GCM field multiply (PMULL)
  hmac.hpp                  # HMAC-SHA-256/384
  hkdf.hpp                  # HKDF and HKDF-Expand
  keccak.hpp                # Keccak-f[1600]
  sha256.hpp                # SHA-256 block compression
  sha3.hpp                  # SHA-3 (256/384/512)
  sha512.hpp                # SHA-512/384 block compression
  CMakeLists.txt
```
