// SPDX-License-Identifier: Apache-2.0

#pragma once

// Poly1305 one-time MAC (RFC 8439 §2.5).
//
// Poly1305 computes a 16-byte tag:
//   tag = ((r * accumulate(msg)) + s) mod 2^128
// where the polynomial is evaluated over GF(2^130 - 5).
//
// Key is 32 bytes: r (16 bytes, clamped) ‖ s (16 bytes).
// r clamping (RFC 8439 §2.5.1):
//   r[3],r[7],r[11],r[15] &= 0x0f
//   r[4],r[8],r[12]       &= 0xfc
//
// Accumulator update for each 17-byte chunk (n ‖ 0x01 for full blocks):
//   acc = (acc + block) * r  mod (2^130 - 5)
//
// Three-limb 44-bit representation:
//   h = h0 + h1*2^44 + h2*2^88   (h0,h1 < 2^44; h2 < 2^42)
//   r = r0 + r1*2^44 + r2*2^88   (after clamping, r2 < 2^36)
//
//   Multiply: (h0+h1*B+h2*B²) * (r0+r1*B+r2*B²)  where B=2^44.
//   Wrapping: B³=2^132=4*2^130 ≡ 20,  B⁴=B*20.
//   So:
//     d0 = h0*r0 + h1*(r2*20) + h2*(r1*20)
//     d1 = h0*r1 + h1*r0     + h2*(r2*20)
//     d2 = h0*r2 + h1*r1     + h2*r0
//   Carry propagation restores the 44/44/42 form.
//
//   This is 9 multiplications vs 25 for the 26-bit 5-limb form, and the
//   compiler maps each __uint128_t product to a MUL+UMULH pair on AArch64.
//
// Four-block parallel processing:
//   For four consecutive full blocks m0, m1, m2, m3:
//     h' = (h + m0)*r⁴ + m1*r³ + m2*r² + m3*r
//   The three right-hand terms are independent of h — the OoO pipeline
//   issues them alongside (h+m0)*r⁴.
//   r², r³, r⁴ are precomputed once per message.

#include <arm_neon.h>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <span>

#include "defs.hpp"
#include "secure_buffer.hpp"


namespace arm_asm::detail {

// Load a 16-byte value as a little-endian 128-bit unsigned integer.
struct Le128 { uint64_t lo, hi; }; // NOLINT(misc-non-private-member-variables-in-classes)

[[nodiscard]]
static inline auto load_le128(const uint8_t* p) noexcept -> Le128 {
    Le128 r{};
    std::memcpy(&r.lo, p,     8);
    std::memcpy(&r.hi, p + 8, 8);
    // On big-endian hosts byteswap; little-endian (Apple Silicon) is a no-op.
    return r;
}

// Store a 16-byte little-endian 128-bit unsigned integer.
static inline void store_le128(uint8_t* p, uint64_t lo, uint64_t hi) noexcept {
    std::memcpy(p,     &lo, 8);
    std::memcpy(p + 8, &hi, 8);
}

// -----------------------------------------------------------------------
// Three-limb 44/44/42-bit accumulator.
// h = h0 + h1*2^44 + h2*2^88
// After normalization: h0,h1 < 2^44; h2 < 2^42.
// -----------------------------------------------------------------------

static constexpr uint64_t mask44 = (1ULL << 44U) - 1U;
static constexpr uint64_t mask42 = (1ULL << 42U) - 1U;

struct Poly1305Limbs {
    uint64_t h0{}, h1{}, h2{}; // NOLINT(misc-non-private-member-variables-in-classes)
};

// Precomputed r^k with reduction constants.
struct Poly1305Precomp {
    uint64_t r0, r1, r2;     // 44/44/40-bit limbs of r^k // NOLINT(misc-non-private-member-variables-in-classes)
    uint64_t r1_20, r2_20;   // r1*20, r2*20 — reduction constants for B³/B⁴ wrap // NOLINT(misc-non-private-member-variables-in-classes)
};

// Extract three 44-bit limbs from a 16-byte block with top bit (0 or 1).
// top=1 for full blocks (sets bit 128), top=0 when the 0x01 is embedded in the data.
[[nodiscard]]
static inline Poly1305Limbs block_to_limbs(uint64_t lo, uint64_t hi,
                                                          uint64_t top) noexcept {
    Poly1305Limbs m;
    m.h0 = lo & mask44;
    m.h1 = ((lo >> 44U) | (hi << 20U)) & mask44;
    m.h2 = (hi >> 24U) | (top << 40U);  // top bit lands at position 128 = 40 in m.h2
    return m;
}

// Clamp r per RFC 8439 §2.5.1 and extract into three 44-bit limbs.
[[nodiscard]]
static inline Poly1305Limbs clamp_r(std::span<const CryptoByte, poly1305_tag_bytes> r_bytes) noexcept {
    FixedSecureBuffer<16> rc;
    std::memcpy(rc.data(), r_bytes.data(), 16);
    rc[ 3] &= 0x0fU;
    rc[ 7] &= 0x0fU;
    rc[11] &= 0x0fU;
    rc[15] &= 0x0fU;
    rc[ 4] &= 0xfcU;
    rc[ 8] &= 0xfcU;
    rc[12] &= 0xfcU;

    uint64_t lo = 0; uint64_t hi = 0;
    std::memcpy(&lo, rc.data(),     8);
    std::memcpy(&hi, rc.data() + 8, 8);
    // r has top 4 bits of each 32-bit chunk cleared → r2 < 2^36
    return Poly1305Limbs{
        .h0 = lo & mask44,
        .h1 = ((lo >> 44U) | (hi << 20U)) & mask44,
        .h2 = hi >> 24U,
    };
}

// Build a Poly1305Precomp (precompute r×20 reduction terms).
[[nodiscard]]
static inline Poly1305Precomp make_precomp(const Poly1305Limbs& r) noexcept {
    return Poly1305Precomp{
        .r0    = r.h0,
        .r1    = r.h1,
        .r2    = r.h2,
        .r1_20 = r.h1 * 20U,
        .r2_20 = r.h2 * 20U,
    };
}

// Multiply accumulator h by precomputed r^k, reduce mod 2^130-5.
// Uses 9 __uint128_t products (→ MUL+UMULH pairs on AArch64).
[[gnu::target("neon")]]
static inline void poly1305_multiply_precomp(Poly1305Limbs& h,
                                              const Poly1305Precomp& p) noexcept {
    using u128 = unsigned __int128;
    const u128 d0 = (static_cast<u128>(h.h0)*p.r0) + (static_cast<u128>(h.h1)*p.r2_20) + (static_cast<u128>(h.h2)*p.r1_20);
    const u128 d1 = (static_cast<u128>(h.h0)*p.r1) + (static_cast<u128>(h.h1)*p.r0)    + (static_cast<u128>(h.h2)*p.r2_20);
    const u128 d2 = (static_cast<u128>(h.h0)*p.r2) + (static_cast<u128>(h.h1)*p.r1)    + (static_cast<u128>(h.h2)*p.r0);

    // Carry propagation: normalize to 44/44/42 form.
    h.h0 = static_cast<uint64_t>(d0) & mask44;  const u128 c1 = d0 >> 44U;
    const u128 e1 = d1 + c1;
    h.h1 = static_cast<uint64_t>(e1) & mask44;  const u128 c2 = e1 >> 44U;
    const u128 e2 = d2 + c2;
    h.h2 = static_cast<uint64_t>(e2) & mask42;
    const uint64_t c3 = static_cast<uint64_t>(e2 >> 42U);  // NOLINT(hicpp-use-auto,modernize-use-auto) — 2^{42+88}=2^130 ≡ 5
    h.h0 += c3 * 5U;
    const uint64_t c4 = h.h0 >> 44U; h.h0 &= mask44; h.h1 += c4;
}

// Add a message block to the accumulator (limb-wise, no carry needed here).
static inline void poly1305_add_block(Poly1305Limbs& h,
                                       uint64_t lo, uint64_t hi,
                                       uint64_t top) noexcept {
    const Poly1305Limbs m = block_to_limbs(lo, hi, top);
    h.h0 += m.h0;
    h.h1 += m.h1;
    h.h2 += m.h2;
}

// Final reduction: ensure h < 2^130-5, then compute (h + s) mod 2^128.
static inline void poly1305_finish(const Poly1305Limbs& h_in,
                                    std::span<const CryptoByte, poly1305_tag_bytes> s_bytes,
                                    std::span<CryptoByte, poly1305_tag_bytes> tag) noexcept
{


    // Propagate any remaining carry into the 44/44/42 form.
    uint64_t h0 = h_in.h0;
    uint64_t h1 = h_in.h1;
    uint64_t h2 = h_in.h2;
    uint64_t c = 0;
    c = h0 >> 44U; h0 &= mask44; h1 += c;
    c = h1 >> 44U; h1 &= mask44; h2 += c;
    c = h2 >> 42U; h2 &= mask42; h0 += c * 5U;
    c = h0 >> 44U; h0 &= mask44; h1 += c;

    // Compute g = h + 5; if g < 2^130, g overflows past the 130-bit field → h >= p.
    const uint64_t g0 = h0 + 5U;
    c = g0 >> 44U;
    const uint64_t g1 = h1 + c;
    c = g1 >> 44U;
    const uint64_t g2 = h2 + c;
    // If g2 >= 2^42, then g >= 2^130, meaning h >= p — use g.
    const uint64_t mask = ((g2 >> 42U) != 0U) ? UINT64_MAX : 0U;

    h0 = (h0 & ~mask) | ((g0 & mask44) & mask);
    h1 = (h1 & ~mask) | ((g1 & mask44) & mask);
    h2 = (h2 & ~mask) | ((g2 & mask42) & mask);

    // Pack 130-bit h to 128-bit little-endian.
    const uint64_t hlo = h0 | (h1 << 44U);
    const uint64_t hhi = (h1 >> 20U) | (h2 << 24U);

    // Add s (mod 2^128).
    const auto [slo, shi] = load_le128(s_bytes.data());
    const uint64_t tlo = hlo + slo;
    const uint64_t thi = hhi + shi + (tlo < hlo ? 1U : 0U);
    store_le128(tag.data(), tlo, thi);
}

// -----------------------------------------------------------------------
// Poly1305Powers: precomputed r^1..r^4 with reduction constants.
// Built once per message; all four parallel chains use a different power.
// -----------------------------------------------------------------------
struct Poly1305Powers {
    Poly1305Precomp p1, p2, p3, p4; // r^1..r^4 // NOLINT(misc-non-private-member-variables-in-classes)

    [[gnu::target("neon")]]
    static Poly1305Powers build(const Poly1305Limbs& r) noexcept {
        Poly1305Powers pw;
        pw.p1 = make_precomp(r);
        Poly1305Limbs r2 = r;  poly1305_multiply_precomp(r2, pw.p1);
        pw.p2 = make_precomp(r2);
        Poly1305Limbs r3 = r2; poly1305_multiply_precomp(r3, pw.p1);
        pw.p3 = make_precomp(r3);
        Poly1305Limbs r4 = r3; poly1305_multiply_precomp(r4, pw.p1);
        pw.p4 = make_precomp(r4);
        return pw;
    }
};

// -----------------------------------------------------------------------
// Four-block parallel: h = (h + m0)*r⁴ + m1*r³ + m2*r² + m3*r
// Three right-hand terms independent of h → OoO pipeline issues all
// four multiply chains simultaneously.
// -----------------------------------------------------------------------
[[gnu::target("neon")]]
static inline void poly1305_process_quad( // NOLINT(readability-function-size,readability-function-cognitive-complexity)
    Poly1305Limbs& h,
    uint64_t m0lo, uint64_t m0hi,
    uint64_t m1lo, uint64_t m1hi,
    uint64_t m2lo, uint64_t m2hi,
    uint64_t m3lo, uint64_t m3hi,
    const Poly1305Powers& pw) noexcept
{
    // Independent chains — no dependency on h.
    Poly1305Limbs x1 = block_to_limbs(m1lo, m1hi, 1U);
    poly1305_multiply_precomp(x1, pw.p3);

    Poly1305Limbs x2 = block_to_limbs(m2lo, m2hi, 1U);
    poly1305_multiply_precomp(x2, pw.p2);

    Poly1305Limbs x3 = block_to_limbs(m3lo, m3hi, 1U);
    poly1305_multiply_precomp(x3, pw.p1);

    // h chain: (h + m0) * r⁴
    poly1305_add_block(h, m0lo, m0hi, 1U);
    poly1305_multiply_precomp(h, pw.p4);

    // Combine and carry-normalize.  After multiply each limb < 2^44, so
    // summing four gives < 4*2^44 = 2^46 — one carry pass is sufficient.
    h.h0 += x1.h0 + x2.h0 + x3.h0;
    h.h1 += x1.h1 + x2.h1 + x3.h1;
    h.h2 += x1.h2 + x2.h2 + x3.h2;
    uint64_t c = 0;
    c = h.h0 >> 44U; h.h0 &= mask44; h.h1 += c;
    c = h.h1 >> 44U; h.h1 &= mask44; h.h2 += c;
    c = h.h2 >> 42U; h.h2 &= mask42; h.h0 += c * 5U;
    c = h.h0 >> 44U; h.h0 &= mask44; h.h1 += c;
}

// Two-block parallel: h = (h + m1)*r² + m2*r
[[gnu::target("neon")]]
static inline void poly1305_process_pair(
    Poly1305Limbs& h,
    uint64_t m1lo, uint64_t m1hi,
    uint64_t m2lo, uint64_t m2hi,
    const Poly1305Powers& pw) noexcept
{
    Poly1305Limbs m2 = block_to_limbs(m2lo, m2hi, 1U);
    poly1305_multiply_precomp(m2, pw.p1);

    poly1305_add_block(h, m1lo, m1hi, 1U);
    poly1305_multiply_precomp(h, pw.p2);

    h.h0 += m2.h0; h.h1 += m2.h1; h.h2 += m2.h2;
    uint64_t c = 0;
    c = h.h0 >> 44U; h.h0 &= mask44; h.h1 += c;
    c = h.h1 >> 44U; h.h1 &= mask44; h.h2 += c;
    c = h.h2 >> 42U; h.h2 &= mask42; h.h0 += c * 5U;
    c = h.h0 >> 44U; h.h0 &= mask44; h.h1 += c;
}


// Compute a Poly1305 tag over msg[] using the 32-byte one-time key.
// key[0..15] = r, key[16..31] = s.
[[gnu::target("neon")]]
inline void poly1305_mac(std::span<const CryptoByte, poly1305_key_bytes> key, const CryptoByte* msg,
                          std::size_t msg_len, std::span<CryptoByte, poly1305_tag_bytes> tag) noexcept
{

    const Poly1305Limbs r   = clamp_r(std::span<const CryptoByte, poly1305_tag_bytes>{key.data(), poly1305_tag_bytes});
    const Poly1305Powers pw = Poly1305Powers::build(r);
    Poly1305Limbs h{};

    std::size_t offset = 0;

    // Primary loop: 4 blocks (64 bytes) at a time.
    while (offset + 64 <= msg_len) {

        const auto [lo0, hi0] = load_le128(msg + offset);

        const auto [lo1, hi1] = load_le128(msg + offset + 16);

        const auto [lo2, hi2] = load_le128(msg + offset + 32);

        const auto [lo3, hi3] = load_le128(msg + offset + 48);
        poly1305_process_quad(h, lo0, hi0, lo1, hi1, lo2, hi2, lo3, hi3, pw);
        offset += 64;
    }

    // Remaining pair.
    if (offset + 32 <= msg_len) {

        const auto [lo1, hi1] = load_le128(msg + offset);

        const auto [lo2, hi2] = load_le128(msg + offset + 16);
        poly1305_process_pair(h, lo1, hi1, lo2, hi2, pw);
        offset += 32;
    }

    // Remaining single full block.
    if (offset + 16 <= msg_len) {

        const auto [lo, hi] = load_le128(msg + offset);
        poly1305_add_block(h, lo, hi, 1U);
        poly1305_multiply_precomp(h, pw.p1);
        offset += 16;
    }

    // Final partial block (if any).
    if (offset < msg_len) {
        std::array<CryptoByte, poly1305_tag_bytes> buf{};

        std::memcpy(buf.data(), msg + offset, msg_len - offset);
        buf[msg_len - offset] = 0x01U;  // RFC 8439: append 0x01 pad byte
        const auto [lo, hi] = load_le128(buf.data());
        poly1305_add_block(h, lo, hi, 0U);  // top bit already embedded
        poly1305_multiply_precomp(h, pw.p1);
    }

    poly1305_finish(h, std::span<const CryptoByte, poly1305_tag_bytes>{key.data() + poly1305_tag_bytes, poly1305_tag_bytes}, tag);
}

}  // namespace arm_asm::detail
