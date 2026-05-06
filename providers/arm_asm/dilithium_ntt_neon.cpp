// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Permanence AI

// NEON-accelerated NTT and invNTT for Dilithium (ML-DSA).
//
// All three ML-DSA parameter sets (44, 65, 87) share q=8380417, N=256, and
// the same zeta table, so a single pair of functions covers all three.
// Each extern "C" wrapper simply calls the shared implementation.
//
// Injection: this translation unit is compiled as an OBJECT library and
// linked before liboqs.a.  Object files are always included in the final
// link, so our definitions of pqcrystals_ml_dsa_{44,65,87}_ref_ntt and
// pqcrystals_ml_dsa_{44,65,87}_ref_invntt_tomont are resolved before the
// linker even consults the liboqs archive.
//
// NEON strategy:
//   Forward NTT (len=128..4): butterfly4 — 4-wide int32x4_t per iteration.
//   Forward NTT (len=2):      butterfly2 — 2-wide int32x2_t per iteration.
//   Forward NTT (len=1):      scalar — 128 single butterfly operations.
//   Inverse NTT mirrors this in reverse order.
//   Final scaling (invNTT):   mont_reduce4 — 4-wide vectorised multiply.
//
// Montgomery reduction for int32 coefficients:
//   For a 64-bit product p = zeta * coef:
//     t = (int32_t)(p * QINV)          [low 32 bits, QINV = q^{-1} mod 2^32]
//     r = (p - (int64_t)t * Q) >> 32   [arithmetic right shift]
//   Result r satisfies -Q < r < Q.

#include <arm_neon.h>
#include <cstdint>

namespace {

static constexpr int32_t k_q    = 8380417;   // modulus
static constexpr int32_t k_qinv = 58728449;  // q^{-1} mod 2^32
static constexpr int32_t k_n    = 256;
static constexpr int32_t k_mont = -4186625;  // 2^32 mod q (Montgomery constant)

// Zeta table — identical across all three ML-DSA parameter sets.
// Sourced from pqcrystals-dilithium-standard_ml-dsa-44_ref/ntt.c.
// NOLINT(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays)
static const int32_t k_zetas[256] = {
         0,    25847, -2608894,  -518909,   237124,  -777960,  -876248,   466468,
   1826347,  2353451,  -359251, -2091905,  3119733, -2884855,  3111497,  2680103,
   2725464,  1024112, -1079900,  3585928,  -549488, -1119584,  2619752, -2108549,
  -2118186, -3859737, -1399561, -3277672,  1757237,   -19422,  4010497,   280005,
   2706023,    95776,  3077325,  3530437, -1661693, -3592148, -2537516,  3915439,
  -3861115, -3043716,  3574422, -2867647,  3539968,  -300467,  2348700,  -539299,
  -1699267, -1643818,  3505694, -3821735,  3507263, -2140649, -1600420,  3699596,
    811944,   531354,   954230,  3881043,  3900724, -2556880,  2071892, -2797779,
  -3930395, -1528703, -3677745, -3041255, -1452451,  3475950,  2176455, -1585221,
  -1257611,  1939314, -4083598, -1000202, -3190144, -3157330, -3632928,   126922,
   3412210,  -983419,  2147896,  2715295, -2967645, -3693493,  -411027, -2477047,
   -671102, -1228525,   -22981, -1308169,  -381987,  1349076,  1852771, -1430430,
  -3343383,   264944,   508951,  3097992,    44288, -1100098,   904516,  3958618,
  -3724342,    -8578,  1653064, -3249728,  2389356,  -210977,   759969, -1316856,
    189548, -3553272,  3159746, -1851402, -2409325,  -177440,  1315589,  1341330,
   1285669, -1584928,  -812732, -1439742, -3019102, -3881060, -3628969,  3839961,
   2091667,  3407706,  2316500,  3817976, -3342478,  2244091, -2446433, -3562462,
    266997,  2434439, -1235728,  3513181, -3520352, -3759364, -1197226, -3193378,
    900702,  1859098,   909542,   819034,   495491, -1613174,   -43260,  -522500,
   -655327, -3122442,  2031748,  3207046, -3556995,  -525098,  -768622, -3595838,
    342297,   286988, -2437823,  4108315,  3437287, -3342277,  1735879,   203044,
   2842341,  2691481, -2590150,  1265009,  4055324,  1247620,  2486353,  1595974,
  -3767016,  1250494,  2635921, -3548272, -2994039,  1869119,  1903435, -1050970,
  -1333058,  1237275, -3318210, -1430225,  -451100,  1312455,  3306115, -1962642,
  -1279661,  1917081, -2546312, -1374803,  1500165,   777191,  2235880,  3406031,
   -542412, -2831860, -1671176, -1846953, -2584293, -3724270,   594136, -3776993,
  -2013608,  2432395,  2454455,  -164721,  1957272,  3369112,   185531, -1207385,
  -3183426,   162844,  1616392,  3014001,   810149,  1652634, -3694233, -1799107,
  -3038916,  3523897,  3866901,   269760,  2213111,  -975884,  1717735,   472078,
   -426683,  1723600, -1803090,  1910376, -1667432, -1104333,  -260646, -3833893,
  -2939036, -2235985,  -420899, -2286327,   183443,  -976891,  1612842, -3545687,
   -554416,  3919660,   -48306, -1362209,  3937738,  1400424,  -846154,  1976782,
};

// Scalar Montgomery reduction.
[[nodiscard]] static inline int32_t mont_reduce(int64_t a) noexcept {
    const int32_t t = static_cast<int32_t>(a) * k_qinv;
    return static_cast<int32_t>((a - static_cast<int64_t>(t) * k_q) >> 32);
}

// -------------------------------------------------------------------------
// NEON Montgomery butterfly helpers (inline, no [[noinline]])
// -------------------------------------------------------------------------

// Montgomery-reduce 4 elements: coef[i] = mont_reduce(f * coef[i]).
static inline void mont_scale4(int32x4_t& v, int32_t f) noexcept {
    const int32x2_t f2    = vdup_n_s32(f);
    const int32x4_t f4    = vdupq_n_s32(f);
    const int32x2_t qinv2 = vdup_n_s32(k_qinv);
    const int32x2_t q2    = vdup_n_s32(k_q);

    int64x2_t p0 = vmull_s32(vget_low_s32(v), f2);
    int64x2_t p1 = vmull_high_s32(v, f4);

    const int32x2_t m0 = vmovn_s64(vmull_s32(vmovn_s64(p0), qinv2));
    const int32x2_t m1 = vmovn_s64(vmull_s32(vmovn_s64(p1), qinv2));

    v = vcombine_s32(
        vshrn_n_s64(vmlsl_s32(p0, m0, q2), 32),
        vshrn_n_s64(vmlsl_s32(p1, m1, q2), 32));
}

// Forward butterfly: lo[i], hi[i]  →  lo[i]+t[i], lo[i]-t[i]
// where t[i] = mont_reduce(zeta * hi[i]).
static inline void butterfly4(int32x4_t& lo, int32x4_t& hi, int32_t zeta) noexcept {
    const int32x2_t zeta2 = vdup_n_s32(zeta);
    const int32x4_t zeta4 = vdupq_n_s32(zeta);
    const int32x2_t qinv2 = vdup_n_s32(k_qinv);
    const int32x2_t q2    = vdup_n_s32(k_q);

    int64x2_t p0 = vmull_s32(vget_low_s32(hi), zeta2);
    int64x2_t p1 = vmull_high_s32(hi, zeta4);

    const int32x2_t m0 = vmovn_s64(vmull_s32(vmovn_s64(p0), qinv2));
    const int32x2_t m1 = vmovn_s64(vmull_s32(vmovn_s64(p1), qinv2));

    const int32x4_t t = vcombine_s32(
        vshrn_n_s64(vmlsl_s32(p0, m0, q2), 32),
        vshrn_n_s64(vmlsl_s32(p1, m1, q2), 32));

    hi = vsubq_s32(lo, t);
    lo = vaddq_s32(lo, t);
}

// 2-wide forward butterfly.
static inline void butterfly2(int32x2_t& lo, int32x2_t& hi, int32_t zeta) noexcept {
    const int32x2_t zeta2 = vdup_n_s32(zeta);
    const int32x2_t qinv2 = vdup_n_s32(k_qinv);
    const int32x2_t q2    = vdup_n_s32(k_q);

    int64x2_t p = vmull_s32(hi, zeta2);

    const int32x2_t m = vmovn_s64(vmull_s32(vmovn_s64(p), qinv2));
    const int32x2_t t = vshrn_n_s64(vmlsl_s32(p, m, q2), 32);

    hi = vsub_s32(lo, t);
    lo = vadd_s32(lo, t);
}

// Inverse butterfly: lo[i], hi[i]  →  lo[i]+hi[i], mont_reduce(zeta*(lo[i]-hi[i]))
static inline void inv_butterfly4(int32x4_t& lo, int32x4_t& hi, int32_t zeta) noexcept {
    const int32x2_t zeta2 = vdup_n_s32(zeta);
    const int32x4_t zeta4 = vdupq_n_s32(zeta);
    const int32x2_t qinv2 = vdup_n_s32(k_qinv);
    const int32x2_t q2    = vdup_n_s32(k_q);

    const int32x4_t t    = lo;
    lo                   = vaddq_s32(t, hi);
    const int32x4_t diff = vsubq_s32(t, hi);

    int64x2_t p0 = vmull_s32(vget_low_s32(diff), zeta2);
    int64x2_t p1 = vmull_high_s32(diff, zeta4);

    const int32x2_t m0 = vmovn_s64(vmull_s32(vmovn_s64(p0), qinv2));
    const int32x2_t m1 = vmovn_s64(vmull_s32(vmovn_s64(p1), qinv2));

    hi = vcombine_s32(
        vshrn_n_s64(vmlsl_s32(p0, m0, q2), 32),
        vshrn_n_s64(vmlsl_s32(p1, m1, q2), 32));
}

// 2-wide inverse butterfly.
static inline void inv_butterfly2(int32x2_t& lo, int32x2_t& hi, int32_t zeta) noexcept {
    const int32x2_t zeta2 = vdup_n_s32(zeta);
    const int32x2_t qinv2 = vdup_n_s32(k_qinv);
    const int32x2_t q2    = vdup_n_s32(k_q);

    const int32x2_t t    = lo;
    lo                   = vadd_s32(t, hi);
    const int32x2_t diff = vsub_s32(t, hi);

    int64x2_t p = vmull_s32(diff, zeta2);

    const int32x2_t m = vmovn_s64(vmull_s32(vmovn_s64(p), qinv2));
    hi = vshrn_n_s64(vmlsl_s32(p, m, q2), 32);
}

// -------------------------------------------------------------------------
// Forward NTT
// -------------------------------------------------------------------------
// NOLINT(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays)
static void dilithium_ntt(int32_t a[]) noexcept {
    unsigned k = 0;

    // Levels len=128 down to len=4: process 4 elements per NEON iteration.
    for (unsigned len = 128; len >= 4; len >>= 1) {
        for (unsigned start = 0; start < static_cast<unsigned>(k_n); start += 2 * len) {
            const int32_t zeta = k_zetas[++k];
            for (unsigned j = start; j < start + len; j += 4) {
                int32x4_t lo = vld1q_s32(a + j);       // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
                int32x4_t hi = vld1q_s32(a + j + len); // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
                butterfly4(lo, hi, zeta);
                vst1q_s32(a + j,       lo); // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
                vst1q_s32(a + j + len, hi); // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
            }
        }
    }

    // Level len=2: 64 groups, 2 elements each — 2-wide NEON.
    for (unsigned start = 0; start < static_cast<unsigned>(k_n); start += 4) {
        const int32_t zeta = k_zetas[++k];
        int32x2_t lo = vld1_s32(a + start);     // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
        int32x2_t hi = vld1_s32(a + start + 2); // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
        butterfly2(lo, hi, zeta);
        vst1_s32(a + start,     lo); // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
        vst1_s32(a + start + 2, hi); // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
    }

    // Level len=1: 128 single pairs — scalar.
    for (unsigned j = 0; j < static_cast<unsigned>(k_n); j += 2) {
        const int32_t zeta = k_zetas[++k];
        const int32_t t    = mont_reduce(static_cast<int64_t>(zeta) * a[j + 1]); // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
        a[j + 1] = a[j] - t; // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
        a[j]     = a[j] + t; // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
    }
}

// -------------------------------------------------------------------------
// Inverse NTT + Montgomery scaling
// -------------------------------------------------------------------------
// NOLINT(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays)
static void dilithium_invntt(int32_t a[]) noexcept {
    unsigned k = static_cast<unsigned>(k_n);  // counts down from 256

    // Level len=1: 128 single pairs — scalar.
    for (unsigned start = 0; start < static_cast<unsigned>(k_n); start += 2) {
        const int32_t zeta = -k_zetas[--k];
        const int32_t t    = a[start];
        a[start]     = t + a[start + 1]; // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
        a[start + 1] = mont_reduce(static_cast<int64_t>(zeta) * (t - a[start + 1])); // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
    }

    // Level len=2: 64 groups, 2 elements each — 2-wide NEON.
    for (unsigned start = 0; start < static_cast<unsigned>(k_n); start += 4) {
        const int32_t zeta = -k_zetas[--k];
        int32x2_t lo = vld1_s32(a + start);     // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
        int32x2_t hi = vld1_s32(a + start + 2); // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
        inv_butterfly2(lo, hi, zeta);
        vst1_s32(a + start,     lo); // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
        vst1_s32(a + start + 2, hi); // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
    }

    // Levels len=4 up to len=128: process 4 elements per NEON iteration.
    for (unsigned len = 4; len < static_cast<unsigned>(k_n); len <<= 1) {
        for (unsigned start = 0; start < static_cast<unsigned>(k_n); start += 2 * len) {
            const int32_t zeta = -k_zetas[--k];
            for (unsigned j = start; j < start + len; j += 4) {
                int32x4_t lo = vld1q_s32(a + j);       // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
                int32x4_t hi = vld1q_s32(a + j + len); // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
                inv_butterfly4(lo, hi, zeta);
                vst1q_s32(a + j,       lo); // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
                vst1q_s32(a + j + len, hi); // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
            }
        }
    }

    // Final Montgomery scaling: a[j] *= mont^2/N = 41978.
    static constexpr int32_t f = 41978;  // mont^2 / 256 mod q
    for (unsigned j = 0; j < static_cast<unsigned>(k_n); j += 4) {
        int32x4_t v = vld1q_s32(a + j); // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
        mont_scale4(v, f);
        vst1q_s32(a + j, v); // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
    }
}

}  // anonymous namespace

// -------------------------------------------------------------------------
// Public C symbols — one thin wrapper per parameter set for NTT and invNTT.
// -------------------------------------------------------------------------
// NOLINT(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays)
extern "C" {

void pqcrystals_ml_dsa_44_ref_ntt(int32_t a[256])        { dilithium_ntt(a);    }
void pqcrystals_ml_dsa_44_ref_invntt_tomont(int32_t a[256]) { dilithium_invntt(a); }

void pqcrystals_ml_dsa_65_ref_ntt(int32_t a[256])        { dilithium_ntt(a);    }
void pqcrystals_ml_dsa_65_ref_invntt_tomont(int32_t a[256]) { dilithium_invntt(a); }

void pqcrystals_ml_dsa_87_ref_ntt(int32_t a[256])        { dilithium_ntt(a);    }
void pqcrystals_ml_dsa_87_ref_invntt_tomont(int32_t a[256]) { dilithium_invntt(a); }

}  // extern "C"
