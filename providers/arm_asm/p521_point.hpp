/*
Copyright Permanence AI, 2026. All rights reserved.

*/

#pragma once

// P-521 (secp521r1) elliptic curve point arithmetic.
//
// Points are in Jacobian projective coordinates: (X:Y:Z) represents
// the affine point (X/Z², Y/Z³).  The point at infinity has Z=0.
//
// Curve equation: y² = x³ − 3x + b  (over GF(p521))
// where b = 0x0051953EB9618E1C9A1F929A21A0B68540EEA2DA725B99B315F3B8B489918EF109E156193951EC7E937B1652C0BD3BB1BF073573DF883D2C34F1EF451FD46B503F00
//
// P-521 generator:
//   Gx = 0x00C6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D3DBAA14B5E77EFE75928FE1DC127A2FFA8DE3348B3C1856A429BF97E7E31C2E5BD66
//   Gy = 0x011839296A789A3BC0045C8A5FB42C7D1BD998F54449579B446817AFBD17273E662C97EE72995EF42640C550B9013FAD0761353C7086A272C24088BE94769FD16650
//
// Group order n = 0x01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409
//
// Key format (PSA raw private key): big-endian 66-byte scalar.
// Key format (PSA uncompressed public key): 0x04 || big-endian 66-byte x || 66-byte y (133 bytes).

#include <cstddef>
#include <cstdint>
#include <cstring>

#include "p521_field.hpp"


namespace arm_asm::detail {


// -----------------------------------------------------------------------
// Curve constants.
// -----------------------------------------------------------------------

static constexpr Fe521 p521_b = {{
    0xef451fd46b503f00ULL,
    0x3573df883d2c34f1ULL,
    0x1652c0bd3bb1bf07ULL,
    0x56193951ec7e937bULL,
    0xb8b489918ef109e1ULL,
    0xa2da725b99b315f3ULL,
    0x929a21a0b68540eeULL,
    0x953eb9618e1c9a1fULL,
    0x0000000000000051ULL,
}};

static constexpr Fe521 p521_Gx = {{
    0xf97e7e31c2e5bd66ULL,
    0x3348b3c1856a429bULL,
    0xfe1dc127a2ffa8deULL,
    0xa14b5e77efe75928ULL,
    0xf828af606b4d3dbaULL,
    0x9c648139053fb521ULL,
    0x9e3ecb662395b442ULL,
    0x858e06b70404e9cdULL,
    0x00000000000000c6ULL,
}};

static constexpr Fe521 p521_Gy = {{
    0x88be94769fd16650ULL,
    0x353c7086a272c240ULL,
    0xc550b9013fad0761ULL,
    0x97ee72995ef42640ULL,
    0x17afbd17273e662cULL,
    0x98f54449579b4468ULL,
    0x5c8a5fb42c7d1bd9ULL,
    0x39296a789a3bc004ULL,
    0x0000000000000118ULL,
}};

// Group order n.
static constexpr uint64_t p521_n[9] = { // NOLINT(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays)
    0xbb6fb71e91386409ULL,
    0x3bb5c9b8899c47aeULL,
    0x7fcc0148f709a5d0ULL,
    0x51868783bf2f966bULL,
    0xfffffffffffffffaULL,
    0xffffffffffffffffULL,
    0xffffffffffffffffULL,
    0xffffffffffffffffULL,
    0x00000000000001ffULL,
};


// -----------------------------------------------------------------------
// Jacobian point and affine point.
// -----------------------------------------------------------------------

struct P521Point {
    Fe521 X;
    Fe521 Y;
    Fe521 Z;
};

struct P521AffinePoint {
    Fe521 X;
    Fe521 Y;
};

static constexpr P521Point p521_identity = {
    .X = fe521_zero,
    .Y = fe521_one,
    .Z = fe521_zero,
};

[[nodiscard]]
static inline auto p521_point_is_identity(const P521Point& p) noexcept -> bool {
    return fe521_is_zero(p.Z);
}


// -----------------------------------------------------------------------
// Point doubling (dbl-2001-b, a=−3 curve).
// -----------------------------------------------------------------------

[[nodiscard]]
static inline auto p521_point_double(const P521Point& p) noexcept -> P521Point {
    if (p521_point_is_identity(p)) { return p; }

    const Fe521 delta = fe521_sqr(p.Z);
    const Fe521 gamma = fe521_sqr(p.Y);
    const Fe521 beta  = fe521_mul(p.X, gamma);

    const Fe521 xmd   = fe521_sub(p.X, delta);
    const Fe521 xpd   = fe521_add(p.X, delta);
    const Fe521 xmxp  = fe521_mul(xmd, xpd);
    const Fe521 alpha = fe521_add(fe521_add(xmxp, xmxp), xmxp);

    const Fe521 beta4 = fe521_add(fe521_add(beta, beta), fe521_add(beta, beta));
    const Fe521 beta8 = fe521_add(beta4, beta4);
    const Fe521 x3    = fe521_sub(fe521_sqr(alpha), beta8);

    const Fe521 z3 = fe521_sub(fe521_sub(fe521_sqr(fe521_add(p.Y, p.Z)), gamma), delta);

    const Fe521 gsq    = fe521_sqr(gamma);
    const Fe521 gsq2   = fe521_add(gsq, gsq);
    const Fe521 gsq4   = fe521_add(gsq2, gsq2);
    const Fe521 gamma8 = fe521_add(gsq4, gsq4);
    const Fe521 y3 = fe521_sub(fe521_mul(alpha, fe521_sub(beta4, x3)), gamma8);

    return P521Point{
        .X = x3,
        .Y = y3,
        .Z = z3,
    };
}


// -----------------------------------------------------------------------
// Point addition (add-2007-bl, full Jacobian).
// -----------------------------------------------------------------------

[[nodiscard]]
static inline auto p521_point_add(const P521Point& p, const P521Point& q) noexcept -> P521Point {
    if (p521_point_is_identity(p)) { return q; }
    if (p521_point_is_identity(q)) { return p; }

    const Fe521 z1sq = fe521_sqr(p.Z);
    const Fe521 z2sq = fe521_sqr(q.Z);
    const Fe521 u1   = fe521_mul(p.X, z2sq);
    const Fe521 u2   = fe521_mul(q.X, z1sq);
    const Fe521 s1   = fe521_mul(p.Y, fe521_mul(q.Z, z2sq));
    const Fe521 s2   = fe521_mul(q.Y, fe521_mul(p.Z, z1sq));
    const Fe521 h    = fe521_sub(u2, u1);
    const Fe521 r    = fe521_sub(s2, s1);

    if (fe521_is_zero(h) && fe521_is_zero(r)) {
        return p521_point_double(p);
    }

    const Fe521 h2   = fe521_sqr(h);
    const Fe521 h3   = fe521_mul(h, h2);
    const Fe521 u1h2 = fe521_mul(u1, h2);
    const Fe521 x3   = fe521_sub(fe521_sub(fe521_sqr(r), h3), fe521_add(u1h2, u1h2));
    const Fe521 y3   = fe521_sub(fe521_mul(r, fe521_sub(u1h2, x3)), fe521_mul(s1, h3));
    const Fe521 z3   = fe521_mul(fe521_mul(h, p.Z), q.Z);

    return P521Point{
        .X = x3,
        .Y = y3,
        .Z = z3,
    };
}


// -----------------------------------------------------------------------
// Mixed Jacobian–affine add: p (Jacobian) + q (affine, Z=1).
// -----------------------------------------------------------------------

[[nodiscard]]
static inline auto p521_point_add_affine(const P521Point& p, const P521AffinePoint& q) noexcept -> P521Point
{
    if (p521_point_is_identity(p)) {
        return P521Point{.X = q.X, .Y = q.Y, .Z = fe521_one};
    }

    const Fe521 z1sq = fe521_sqr(p.Z);
    const Fe521 u2   = fe521_mul(q.X, z1sq);
    const Fe521 s2   = fe521_mul(q.Y, fe521_mul(p.Z, z1sq));
    const Fe521 h    = fe521_sub(u2, p.X);
    const Fe521 r    = fe521_sub(s2, p.Y);

    if (fe521_is_zero(h) && fe521_is_zero(r)) {
        return p521_point_double(p);
    }

    const Fe521 h2   = fe521_sqr(h);
    const Fe521 h3   = fe521_mul(h, h2);
    const Fe521 u1h2 = fe521_mul(p.X, h2);
    const Fe521 x3   = fe521_sub(fe521_sub(fe521_sqr(r), h3), fe521_add(u1h2, u1h2));
    const Fe521 y3   = fe521_sub(fe521_mul(r, fe521_sub(u1h2, x3)), fe521_mul(p.Y, h3));
    const Fe521 z3   = fe521_mul(h, p.Z);

    return P521Point{
        .X = x3,
        .Y = y3,
        .Z = z3,
    };
}


// -----------------------------------------------------------------------
// Precomputed [1..15]*G table for 4-bit fixed-base window.
// -----------------------------------------------------------------------

static constexpr P521AffinePoint p521_G_table[15] = { // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    // [1]*G
    {{0xf97e7e31c2e5bd66ULL, 0x3348b3c1856a429bULL, 0xfe1dc127a2ffa8deULL, 0xa14b5e77efe75928ULL, 0xf828af606b4d3dbaULL, 0x9c648139053fb521ULL, 0x9e3ecb662395b442ULL, 0x858e06b70404e9cdULL, 0x00000000000000c6ULL}, {0x88be94769fd16650ULL, 0x353c7086a272c240ULL, 0xc550b9013fad0761ULL, 0x97ee72995ef42640ULL, 0x17afbd17273e662cULL, 0x98f54449579b4468ULL, 0x5c8a5fb42c7d1bd9ULL, 0x39296a789a3bc004ULL, 0x0000000000000118ULL}},
    // [2]*G
    {{0xf43e3933ba6d783dULL, 0xcf2fa364d60fd967ULL, 0xaa104a3a35c5af41ULL, 0xb3b204da6ef55507ULL, 0x2c6e5505d769be97ULL, 0x7403279b1ccc0635ULL, 0x2fcb288148c28274ULL, 0x3c219024277e7e68ULL, 0x0000000000000043ULL}, {0x1be356d661f41b02ULL, 0xeafcbe95edc0f4f7ULL, 0x93937fa99a3248f4ULL, 0xb3e377de9f251f6bULL, 0xab21a29906c42dbbULL, 0xc6b5107c4da97740ULL, 0xa7f3eceeeed3f0b5ULL, 0xbb8cc7f86db26700ULL, 0x00000000000000f4ULL}},
    // [3]*G
    {{0xa5919d2ede37ad7dULL, 0xaeb490862c32ea05ULL, 0x1da6bd16b59fe21bULL, 0xad3f164a3a483205ULL, 0xe5ad7a112d7a8dd1ULL, 0xb52a6e5b123d9ab9ULL, 0xd91d6a64b5959479ULL, 0x3d352443de29195dULL, 0x00000000000001a7ULL}, {0x5f588ca1ee86c0e5ULL, 0xf105c9bc93a59042ULL, 0x2d5aced1dec3c70cULL, 0x2e2dd4cf8dc575b0ULL, 0xd2f8ab1fa355ceecULL, 0xf1557fa82a9d0317ULL, 0x979f86c6cab814f2ULL, 0x9b03b97dfa62ddd9ULL, 0x000000000000013eULL}},
    // [4]*G
    {{0xfbc87412871902f3ULL, 0xa1d5025b08e5a5e2ULL, 0xe8b88e9f078af066ULL, 0x8659e24afe3d0750ULL, 0x06c5d55541d3ceacULL, 0xc61c891c5ff39afcULL, 0x54b483487c9070cdULL, 0xb5df64ae2ac204c3ULL, 0x0000000000000035ULL}, {0xe21f47fc346e4d0dULL, 0xbb7faef04699d1d9ULL, 0x5224f750a95b85eeULL, 0x79f283e54ba38540ULL, 0x5ae63fe2f19907f2ULL, 0x5521aef6e6e32e1bULL, 0x73e0178eb0b4abb6ULL, 0x096f84261279d2b6ULL, 0x0000000000000082ULL}},
    // [5]*G
    {{0xd5ab5096ec8f3078ULL, 0x29d7e1e6d8931738ULL, 0x7112feaf137e79a3ULL, 0x383c0c6d5e301423ULL, 0xcf03dab8f177ace4ULL, 0x7a596efdb53f0d24ULL, 0x3dbc3391c04eb0bfULL, 0x2bf3c52927a432c7ULL, 0x0000000000000065ULL}, {0x173cc3e8deb090cbULL, 0xd1f007257354f7f8ULL, 0x311540211cf5ff79ULL, 0xbb6897c9072cf374ULL, 0xedd817c9a0347087ULL, 0x1cd8fe8e872e0051ULL, 0x8a2b73114a811291ULL, 0xe6ef1bdd6601d6ecULL, 0x000000000000015bULL}},
    // [6]*G
    {{0x23731bedf79206b9ULL, 0x2f66e95657f380aeULL, 0xe0727a239531be8cULL, 0x5fbcca16153f7394ULL, 0x981506ade4ab0152ULL, 0x623d30977fd71cf3ULL, 0x2eff34f94480d195ULL, 0x4569d6cdb5921953ULL, 0x00000000000001eeULL}, {0x1eaccd7858d44f17ULL, 0x3dc7b8b55ca0dadeULL, 0xf96c984de274f220ULL, 0xcab72d0e56648c9dULL, 0x7240a926201a8a96ULL, 0x2aabbb73da5a808eULL, 0xe2dd270546e3b111ULL, 0x0255ad0cc64f586aULL, 0x00000000000001deULL}},
    // [7]*G
    {{0x01cead882816ecd4ULL, 0x6f953f50fdc2619aULL, 0xc9a6df30dce3bbc4ULL, 0x8c308d0abfc698d8ULL, 0xf018d2c2f7114c5dULL, 0x5f22e0e8f5483228ULL, 0xeeb65fda0b073a0cULL, 0xd5d1d99d5b7f6346ULL, 0x0000000000000056ULL}, {0x5c6b8bc90525251bULL, 0x9e76712a5ddefc7bULL, 0x9523a34591ce1a5fULL, 0x6bd0f293cdec9e2bULL, 0x71dbd98a26cbde55ULL, 0xb5c582d02824f0ddULL, 0xd1d8317a39d68478ULL, 0x2d1b7d9baaa2a110ULL, 0x000000000000003dULL}},
    // [8]*G
    {{0x86f9ea54aa78ce68ULL, 0xb56289b5a6f40405ULL, 0x8b598c1bc8d79e1aULL, 0x5bfea5b8579f49f0ULL, 0x8b8a3b05f826298fULL, 0xd4e29d8a9b003e0aULL, 0xa8348396b010e25bULL, 0x22c40fb6301f7262ULL, 0x0000000000000008ULL}, {0x8ad642f11f17801cULL, 0x9f3ba94009471353ULL, 0xf0ba0df065c57869ULL, 0x89e9c0aa5911b4bfULL, 0x5083de610677a8f1ULL, 0x44f8ede9e2c0715bULL, 0x48fdab6e78853b9aULL, 0x31911d5542fc4820ULL, 0x0000000000000163ULL}},
    // [9]*G
    {{0x1f45627967cbe207ULL, 0x4f50babd85cd2866ULL, 0xf3c556df725a318fULL, 0x7429e1396134da35ULL, 0x2c4ab145b8c6b665ULL, 0xed34541b98874699ULL, 0xa2f5bf157156d488ULL, 0x5389e359e1e21826ULL, 0x0000000000000158ULL}, {0x3aa0ea86b9ad2a4eULL, 0x736c2ae928880f34ULL, 0x0ff56ecf4abfd87dULL, 0x0d69e5756057ac84ULL, 0xc825ba263ddb446eULL, 0x3088a654ee1cebb6ULL, 0x0b55557a27ae938eULL, 0x2e618c9a8aedf39fULL, 0x000000000000002aULL}},
    // [10]*G
    {{0x87ff09a04f2f3320ULL, 0x7c2e411f1a8e819aULL, 0x9daa4da9842093f3ULL, 0xa2c7c178fcc26329ULL, 0x4a9246b11ada8910ULL, 0x901d879ac09ac7c3ULL, 0xfcfe7bb6721ec4cdULL, 0xeb8f22bda61f281dULL, 0x0000000000000190ULL}, {0x2954bc98135ec759ULL, 0xf3689639739faa17ULL, 0x536f6163dc57ebefULL, 0xbf5349d44d9864bbULL, 0xa97fd78a62ef62d2ULL, 0xc2eeb2144251b20bULL, 0xbaeab3b0ca2ba760ULL, 0x5d96b8491614ba9dULL, 0x00000000000001ebULL}},
    // [11]*G
    {{0xecc0e02dda0cdb9aULL, 0x015c024fa4c9a902ULL, 0xd19b1aebe3191085ULL, 0xf3dbc5332663da1bULL, 0x43ef2c54f2991652ULL, 0xed5dc7ed7c178495ULL, 0x6f1a39573b4315cfULL, 0x75841259fdedff54ULL, 0x000000000000008aULL}, {0x58874f92ce48c808ULL, 0xdcac80e3f4819b5dULL, 0x3892331914a95336ULL, 0x1bc8a90e8b42a4abULL, 0xed2e95d4e0b9b82bULL, 0x3add566210bd0493ULL, 0x9d0ca877054fb229ULL, 0xfb303fcbba212984ULL, 0x0000000000000096ULL}},
    // [12]*G
    {{0x7be69571bf842d8cULL, 0x3774c75c530928b1ULL, 0x477fee9a60e93801ULL, 0x44e90b7c3fb81b31ULL, 0x107cf7a5967713a6ULL, 0x81874157958457b6ULL, 0xe4fae9749c7fde1eULL, 0xd9dcec93f8221c5dULL, 0x00000000000001c0ULL}, {0x79e7b1a3281b17f0ULL, 0x884ba72224f5ae6cULL, 0xcc10a6f951b9b630ULL, 0xd6d18843d86fcdb6ULL, 0x5e404abf6a17c097ULL, 0x63fe65ab71494da4ULL, 0x3ce1d103a682ca47ULL, 0x48b5946a4927c0feULL, 0x0000000000000140ULL}},
    // [13]*G
    {{0x1887848d32fbcda7ULL, 0x4bec3b00ab38eff8ULL, 0x3550a5e79ab88ee9ULL, 0x32c45908e03c996aULL, 0x4eedd2beaf5b8661ULL, 0x93f736cde1b4c238ULL, 0xd7865d2b4924861aULL, 0x3e98f984c396ad9cULL, 0x000000000000007eULL}, {0x291a01fb022a71c9ULL, 0x6199eaaf9117e9f7ULL, 0x26dfdd351cbfbbc3ULL, 0xc1bd5d5838bc763fULL, 0x9c7a67ae5c1e212aULL, 0xced50a386d5421c6ULL, 0x1a1926daa3ed5a08ULL, 0xee58eb6d781feda9ULL, 0x0000000000000108ULL}},
    // [14]*G
    {{0x2c9e682dd3432d74ULL, 0x6767f6b812efbf5dULL, 0x79df3e4b7bc744aaULL, 0x74fc06c8b897222dULL, 0xd4fb0babe0b31999ULL, 0x958b401494116a2fULL, 0xe1b8ccfaaf84ded1ULL, 0x5bc7dc551b1b65a9ULL, 0x0000000000000187ULL}, {0x41669f852700d54aULL, 0x5b690f53a87c84beULL, 0x11e89bf1d133dc0dULL, 0xd07781b1b4f3584cULL, 0x0847ce9b86d7ed62ULL, 0x8470122b8e51826aULL, 0xd66290bbabb4bdfbULL, 0xa4923575dacb5bd2ULL, 0x000000000000005cULL}},
    // [15]*G
    {{0xe9afe337bcb8db55ULL, 0x9b8d96981e3f92bdULL, 0x7875bd1c8fc0331dULL, 0xb91cce27dbd00ffeULL, 0xd697b532df128e11ULL, 0xb8fbcc30b40a0852ULL, 0x41558fc546d4300fULL, 0x6ad89abcb92465f0ULL, 0x000000000000006bULL}, {0x56343480a1475465ULL, 0x46fd90cc446abdd9ULL, 0x2148e2232c96c992ULL, 0x7e9062c899470a80ULL, 0x4b62106997485ed5ULL, 0xdf0496a9bad20cbaULL, 0x7ce64d2333edbf63ULL, 0x68da271571391d6aULL, 0x00000000000001b4ULL}},
}; // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)


// -----------------------------------------------------------------------
// Fixed-base scalar multiplication using 4-bit window: k·G.
// scalar is 66-byte big-endian.
// -----------------------------------------------------------------------

[[nodiscard]]
static inline auto p521_scalar_mul_base( // NOLINT(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays)
    const uint8_t scalar[66]) noexcept -> P521Point // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
{
    P521Point result = p521_identity;

    // P-521 is 521 bits = 65 full bytes + 1 bit in byte[0].
    // Process byte[0] (only its low bit) as a 1-bit step first, then bytes 1..65 as 4-bit nibbles.
    // We process MSB-first: byte[0] high nibble would be bits 520..524 (beyond the field), so
    // the top byte contributes only 1 bit (bit 520). Process it with a single doubling + conditional add.

    // Process the single top bit: scalar[0] bit 0 (the 521st bit, MSB of the scalar).
    {
        result = p521_point_double(result);
        const auto nibble = static_cast<unsigned>(scalar[0] & 0x01U); // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
        if (nibble != 0U) {
            result = p521_point_add_affine(result, p521_G_table[nibble - 1U]); // NOLINT(cppcoreguidelines-pro-bounds-constant-array-index)
        }
    }

    // Process bytes 1..65 as full byte pairs of nibbles.
    for (int byte_i = 1; byte_i < 66; ++byte_i) { // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
        const uint8_t byte_val = scalar[byte_i]; // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)

        for (int pass = 0; pass < 2; ++pass) {
            result = p521_point_double(result);
            result = p521_point_double(result);
            result = p521_point_double(result);
            result = p521_point_double(result);

            const auto nibble = static_cast<unsigned>(
                (pass == 0) ? (byte_val >> 4U) : (byte_val & 0x0fU));

            if (nibble != 0U) {
                result = p521_point_add_affine(result, p521_G_table[nibble - 1U]); // NOLINT(cppcoreguidelines-pro-bounds-constant-array-index)
            }
        }
    }
    return result;
}


// -----------------------------------------------------------------------
// Convert Jacobian → affine.
// -----------------------------------------------------------------------

[[nodiscard]]
static inline auto p521_to_affine(const P521Point& p) noexcept -> P521Point {
    if (p521_point_is_identity(p)) { return p; }
    const Fe521 zinv  = fe521_invert(p.Z);
    const Fe521 zinv2 = fe521_sqr(zinv);
    const Fe521 zinv3 = fe521_mul(zinv, zinv2);
    return P521Point{
        .X = fe521_mul(p.X, zinv2),
        .Y = fe521_mul(p.Y, zinv3),
        .Z = fe521_one,
    };
}


// -----------------------------------------------------------------------
// Constant-time scalar multiplication: k·base.
// scalar is a 521-bit big-endian byte array (66 bytes).
// -----------------------------------------------------------------------

[[nodiscard]]
static inline auto p521_scalar_mul( // NOLINT(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays)
    const P521Point& base, const uint8_t scalar[66]) noexcept -> P521Point // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
{
    P521Point result = p521_identity;
    P521Point tmp    = base;

    // Process 65 full bytes (bits 0–519) and the low 9 bits of byte[0].
    // scalar[65] is LSB, scalar[0] is MSB (big-endian).
    // We iterate LSB to MSB: byte 65 down to byte 0, bit 0 to bit 7 per byte,
    // but byte 0 only contributes 1 bit (bit 0, i.e. the 521st bit = bit 520).
    for (int byte_i = 65; byte_i >= 1; --byte_i) { // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
        const uint8_t byte_val = scalar[byte_i]; // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
        for (int bit = 0; bit < 8; ++bit) {
            const uint64_t k_bit = (static_cast<uint64_t>(byte_val) >> static_cast<unsigned>(bit)) & 1U;
            const P521Point added = p521_point_add(result, tmp);
            const uint64_t mask = 0U - k_bit;
            for (int i = 0; i < 9; ++i) { // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
                result.X.v[i] = (added.X.v[i] & mask) | (result.X.v[i] & ~mask);
                result.Y.v[i] = (added.Y.v[i] & mask) | (result.Y.v[i] & ~mask);
                result.Z.v[i] = (added.Z.v[i] & mask) | (result.Z.v[i] & ~mask);
            }
            tmp = p521_point_double(tmp);
        }
    }
    // Process the top byte: only 1 bit (bit 0 of scalar[0]).
    {
        const uint64_t k_bit = static_cast<uint64_t>(scalar[0]) & 1U; // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
        const P521Point added = p521_point_add(result, tmp);
        const uint64_t mask = 0U - k_bit;
        for (int i = 0; i < 9; ++i) { // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
            result.X.v[i] = (added.X.v[i] & mask) | (result.X.v[i] & ~mask);
            result.Y.v[i] = (added.Y.v[i] & mask) | (result.Y.v[i] & ~mask);
            result.Z.v[i] = (added.Z.v[i] & mask) | (result.Z.v[i] & ~mask);
        }
    }
    return result;
}


// -----------------------------------------------------------------------
// Scalar arithmetic mod n.
// -----------------------------------------------------------------------

[[nodiscard]]
static inline auto p521_scalar_from_bytes66( // NOLINT(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays)
    const uint8_t b[66]) noexcept -> Fe521 // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
{
    // Load as field element, then conditionally subtract n once.
    Fe521 r{};
    for (int i = 0; i < 8; ++i) { // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
        const uint8_t* p = b + (65 - i * 8); // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic,cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
        r.v[i] =
            (static_cast<uint64_t>(p[-7]) << 56U) | (static_cast<uint64_t>(p[-6]) << 48U) | // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
            (static_cast<uint64_t>(p[-5]) << 40U) | (static_cast<uint64_t>(p[-4]) << 32U) | // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
            (static_cast<uint64_t>(p[-3]) << 24U) | (static_cast<uint64_t>(p[-2]) << 16U) | // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
            (static_cast<uint64_t>(p[-1]) <<  8U) |  static_cast<uint64_t>(p[0]);           // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
    }
    r.v[8] = (static_cast<uint64_t>(b[0]) << 8U) | static_cast<uint64_t>(b[1]); // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic,cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    r.v[8] &= 0x1ffULL;

    // Conditional subtract n.
    using u128 = unsigned __int128;
    Fe521 sub{};
    auto t = static_cast<u128>(r.v[0]) - p521_n[0];
    sub.v[0] = static_cast<uint64_t>(t);
    auto borrow = static_cast<uint64_t>(t >> 127U);
    t = static_cast<u128>(r.v[1]) - p521_n[1] - borrow;
    sub.v[1] = static_cast<uint64_t>(t);
    borrow = static_cast<uint64_t>(t >> 127U);
    t = static_cast<u128>(r.v[2]) - p521_n[2] - borrow;
    sub.v[2] = static_cast<uint64_t>(t);
    borrow = static_cast<uint64_t>(t >> 127U);
    t = static_cast<u128>(r.v[3]) - p521_n[3] - borrow;
    sub.v[3] = static_cast<uint64_t>(t);
    borrow = static_cast<uint64_t>(t >> 127U);
    t = static_cast<u128>(r.v[4]) - p521_n[4] - borrow;
    sub.v[4] = static_cast<uint64_t>(t);
    borrow = static_cast<uint64_t>(t >> 127U);
    t = static_cast<u128>(r.v[5]) - p521_n[5] - borrow;
    sub.v[5] = static_cast<uint64_t>(t);
    borrow = static_cast<uint64_t>(t >> 127U);
    t = static_cast<u128>(r.v[6]) - p521_n[6] - borrow;
    sub.v[6] = static_cast<uint64_t>(t);
    borrow = static_cast<uint64_t>(t >> 127U);
    t = static_cast<u128>(r.v[7]) - p521_n[7] - borrow;
    sub.v[7] = static_cast<uint64_t>(t);
    borrow = static_cast<uint64_t>(t >> 127U);
    t = static_cast<u128>(r.v[8]) - p521_n[8] - borrow;
    sub.v[8] = static_cast<uint64_t>(t) & 0x1ffULL;
    borrow = static_cast<uint64_t>(t >> 127U);
    const uint64_t mask = 0U - (1U - borrow);
    return Fe521{{
        (sub.v[0] & mask) | (r.v[0] & ~mask),
        (sub.v[1] & mask) | (r.v[1] & ~mask),
        (sub.v[2] & mask) | (r.v[2] & ~mask),
        (sub.v[3] & mask) | (r.v[3] & ~mask),
        (sub.v[4] & mask) | (r.v[4] & ~mask),
        (sub.v[5] & mask) | (r.v[5] & ~mask),
        (sub.v[6] & mask) | (r.v[6] & ~mask),
        (sub.v[7] & mask) | (r.v[7] & ~mask),
        (sub.v[8] & mask) | (r.v[8] & ~mask),
    }};
}

// Load a hash of hlen bytes (< qlen=66) as a scalar: zero-pad on the left to 66 bytes.
[[nodiscard]]
static inline auto p521_scalar_from_bytes66_hash( // NOLINT(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays)
    const uint8_t* hash_be, std::size_t hlen) noexcept -> Fe521
{
    uint8_t padded[66] = {}; // NOLINT(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays,cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    const std::size_t qlen = 66; // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    if (hlen >= qlen) {
        std::memcpy(padded, hash_be, qlen);
    } else {
        std::memcpy(padded + (qlen - hlen), hash_be, hlen); // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
    }
    return p521_scalar_from_bytes66(padded);
}

[[nodiscard]]
static inline auto p521_scalar_add( // NOLINT(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays)
    const Fe521& a, const Fe521& b) noexcept -> Fe521
{
    using u128 = unsigned __int128;
    auto t = static_cast<u128>(a.v[0]) + b.v[0];
    Fe521 r{};
    r.v[0] = static_cast<uint64_t>(t);
    t = static_cast<u128>(a.v[1]) + b.v[1] + (t >> 64U);
    r.v[1] = static_cast<uint64_t>(t);
    t = static_cast<u128>(a.v[2]) + b.v[2] + (t >> 64U);
    r.v[2] = static_cast<uint64_t>(t);
    t = static_cast<u128>(a.v[3]) + b.v[3] + (t >> 64U);
    r.v[3] = static_cast<uint64_t>(t);
    t = static_cast<u128>(a.v[4]) + b.v[4] + (t >> 64U);
    r.v[4] = static_cast<uint64_t>(t);
    t = static_cast<u128>(a.v[5]) + b.v[5] + (t >> 64U);
    r.v[5] = static_cast<uint64_t>(t);
    t = static_cast<u128>(a.v[6]) + b.v[6] + (t >> 64U);
    r.v[6] = static_cast<uint64_t>(t);
    t = static_cast<u128>(a.v[7]) + b.v[7] + (t >> 64U);
    r.v[7] = static_cast<uint64_t>(t);
    t = static_cast<u128>(a.v[8]) + b.v[8] + (t >> 64U);
    r.v[8] = static_cast<uint64_t>(t);
    const uint64_t overflow = static_cast<uint64_t>(t >> 64U);

    Fe521 sub{};
    auto s = static_cast<u128>(r.v[0]) - p521_n[0];
    sub.v[0] = static_cast<uint64_t>(s);
    auto borrow = static_cast<uint64_t>(s >> 127U);
    s = static_cast<u128>(r.v[1]) - p521_n[1] - borrow;
    sub.v[1] = static_cast<uint64_t>(s);
    borrow = static_cast<uint64_t>(s >> 127U);
    s = static_cast<u128>(r.v[2]) - p521_n[2] - borrow;
    sub.v[2] = static_cast<uint64_t>(s);
    borrow = static_cast<uint64_t>(s >> 127U);
    s = static_cast<u128>(r.v[3]) - p521_n[3] - borrow;
    sub.v[3] = static_cast<uint64_t>(s);
    borrow = static_cast<uint64_t>(s >> 127U);
    s = static_cast<u128>(r.v[4]) - p521_n[4] - borrow;
    sub.v[4] = static_cast<uint64_t>(s);
    borrow = static_cast<uint64_t>(s >> 127U);
    s = static_cast<u128>(r.v[5]) - p521_n[5] - borrow;
    sub.v[5] = static_cast<uint64_t>(s);
    borrow = static_cast<uint64_t>(s >> 127U);
    s = static_cast<u128>(r.v[6]) - p521_n[6] - borrow;
    sub.v[6] = static_cast<uint64_t>(s);
    borrow = static_cast<uint64_t>(s >> 127U);
    s = static_cast<u128>(r.v[7]) - p521_n[7] - borrow;
    sub.v[7] = static_cast<uint64_t>(s);
    borrow = static_cast<uint64_t>(s >> 127U);
    s = static_cast<u128>(r.v[8]) - p521_n[8] - borrow;
    sub.v[8] = static_cast<uint64_t>(s) & 0x1ffULL;
    borrow = static_cast<uint64_t>(s >> 127U);
    const uint64_t use_sub = overflow | (1U - borrow);
    const uint64_t mask = 0U - use_sub;
    return Fe521{{
        (sub.v[0] & mask) | (r.v[0] & ~mask),
        (sub.v[1] & mask) | (r.v[1] & ~mask),
        (sub.v[2] & mask) | (r.v[2] & ~mask),
        (sub.v[3] & mask) | (r.v[3] & ~mask),
        (sub.v[4] & mask) | (r.v[4] & ~mask),
        (sub.v[5] & mask) | (r.v[5] & ~mask),
        (sub.v[6] & mask) | (r.v[6] & ~mask),
        (sub.v[7] & mask) | (r.v[7] & ~mask),
        (sub.v[8] & mask) | (r.v[8] & ~mask),
    }};
}

// Montgomery CIOS multiplication mod n for P-521.
// Computes a*b*R^{-1} mod n where R = 2^576 (9 × 64-bit limbs).
// n_prime = -n[0]^{-1} mod 2^64 = 0x1d2f5ccd79a995c7
[[nodiscard]]
static inline auto p521_mont_mul_n(const Fe521& a, const Fe521& b) noexcept -> Fe521
{
    using u128 = unsigned __int128;
    constexpr int s = 9; // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    constexpr uint64_t n_prime = 0x1d2f5ccd79a995c7ULL;

    uint64_t t[s + 2]{}; // NOLINT(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays)
    for (int i = 0; i < s; ++i) {
        uint64_t carry = 0;
        for (int j = 0; j < s; ++j) {
            const u128 tt = static_cast<u128>(a.v[i]) * b.v[j] + t[j] + carry;
            t[j]  = static_cast<uint64_t>(tt);
            carry = static_cast<uint64_t>(tt >> 64U);
        }
        u128 tt = static_cast<u128>(t[s]) + carry;
        t[s]     = static_cast<uint64_t>(tt);
        t[s + 1] = static_cast<uint64_t>(tt >> 64U);

        const uint64_t m = t[0] * n_prime;
        tt = static_cast<u128>(m) * p521_n[0] + t[0];
        carry = static_cast<uint64_t>(tt >> 64U);
        for (int j = 1; j < s; ++j) {
            tt       = static_cast<u128>(m) * p521_n[j] + t[j] + carry;
            t[j - 1] = static_cast<uint64_t>(tt);
            carry    = static_cast<uint64_t>(tt >> 64U);
        }
        tt = static_cast<u128>(t[s]) + carry;
        t[s - 1] = static_cast<uint64_t>(tt);
        carry    = static_cast<uint64_t>(tt >> 64U);
        tt = static_cast<u128>(t[s + 1]) + carry;
        t[s]     = static_cast<uint64_t>(tt);
        t[s + 1] = 0;
    }

    Fe521 r{{t[0], t[1], t[2], t[3], t[4], t[5], t[6], t[7], t[8]}}; // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    const uint64_t overflow = t[s];

    Fe521 sub{};
    auto st = static_cast<u128>(r.v[0]) - p521_n[0];
    sub.v[0] = static_cast<uint64_t>(st);
    auto borrow = static_cast<uint64_t>(st >> 127U);
    st = static_cast<u128>(r.v[1]) - p521_n[1] - borrow;
    sub.v[1] = static_cast<uint64_t>(st);
    borrow = static_cast<uint64_t>(st >> 127U);
    st = static_cast<u128>(r.v[2]) - p521_n[2] - borrow;
    sub.v[2] = static_cast<uint64_t>(st);
    borrow = static_cast<uint64_t>(st >> 127U);
    st = static_cast<u128>(r.v[3]) - p521_n[3] - borrow;
    sub.v[3] = static_cast<uint64_t>(st);
    borrow = static_cast<uint64_t>(st >> 127U);
    st = static_cast<u128>(r.v[4]) - p521_n[4] - borrow;
    sub.v[4] = static_cast<uint64_t>(st);
    borrow = static_cast<uint64_t>(st >> 127U);
    st = static_cast<u128>(r.v[5]) - p521_n[5] - borrow;
    sub.v[5] = static_cast<uint64_t>(st);
    borrow = static_cast<uint64_t>(st >> 127U);
    st = static_cast<u128>(r.v[6]) - p521_n[6] - borrow;
    sub.v[6] = static_cast<uint64_t>(st);
    borrow = static_cast<uint64_t>(st >> 127U);
    st = static_cast<u128>(r.v[7]) - p521_n[7] - borrow;
    sub.v[7] = static_cast<uint64_t>(st);
    borrow = static_cast<uint64_t>(st >> 127U);
    st = static_cast<u128>(r.v[8]) - p521_n[8] - borrow;
    sub.v[8] = static_cast<uint64_t>(st) & 0x1ffULL;
    borrow = static_cast<uint64_t>(st >> 127U);
    const uint64_t use_sub = overflow | (1U - borrow);
    const uint64_t mask = 0U - use_sub;
    return Fe521{{
        (sub.v[0] & mask) | (r.v[0] & ~mask),
        (sub.v[1] & mask) | (r.v[1] & ~mask),
        (sub.v[2] & mask) | (r.v[2] & ~mask),
        (sub.v[3] & mask) | (r.v[3] & ~mask),
        (sub.v[4] & mask) | (r.v[4] & ~mask),
        (sub.v[5] & mask) | (r.v[5] & ~mask),
        (sub.v[6] & mask) | (r.v[6] & ~mask),
        (sub.v[7] & mask) | (r.v[7] & ~mask),
        (sub.v[8] & mask) | (r.v[8] & ~mask),
    }};
}

// Scalar mod-n multiply: a*b mod n.
// R^2 mod n (R=2^576):
[[nodiscard]]
static inline auto p521_scalar_mul_mod_n(
    const Fe521& a, const Fe521& b) noexcept -> Fe521
{
    static constexpr Fe521 r2_mod_n = {{
        0x137cd04dcf15dd04ULL,
        0xf707badce5547ea3ULL,
        0x12a78d38794573ffULL,
        0xd3721ef557f75e06ULL,
        0xdd6e23d82e49c7dbULL,
        0xcff3d142b7756e3eULL,
        0x5bcc6d61a8e567bcULL,
        0x2d8e03d1492d0d45ULL,
        0x000000000000003dULL,
    }};
    const Fe521 a_mont = p521_mont_mul_n(a, r2_mod_n);
    return p521_mont_mul_n(a_mont, b);
}

[[nodiscard]]
static inline auto p521_scalar_invert(const Fe521& a) noexcept -> Fe521 {
    static constexpr uint64_t nm2[9] = { // NOLINT(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays)
        0xbb6fb71e91386407ULL,
        0x3bb5c9b8899c47aeULL,
        0x7fcc0148f709a5d0ULL,
        0x51868783bf2f966bULL,
        0xfffffffffffffffaULL,
        0xffffffffffffffffULL,
        0xffffffffffffffffULL,
        0xffffffffffffffffULL,
        0x00000000000001ffULL,
    };
    Fe521 result{{1ULL, 0ULL, 0ULL, 0ULL, 0ULL, 0ULL, 0ULL, 0ULL, 0ULL}};
    for (int word = 8; word >= 0; --word) { // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
        const int bits = (word == 8) ? 9 : 64; // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
        for (int bit = bits - 1; bit >= 0; --bit) {
            result = p521_scalar_mul_mod_n(result, result);
            if (((nm2[word] >> static_cast<unsigned>(bit)) & 1U) != 0U) {
                result = p521_scalar_mul_mod_n(result, a);
            }
        }
    }
    return result;
}

[[nodiscard]]
static inline auto p521_scalar_is_zero(const Fe521& a) noexcept -> bool {
    return (a.v[0] | a.v[1] | a.v[2] | a.v[3] | a.v[4] |
            a.v[5] | a.v[6] | a.v[7] | a.v[8]) == 0U;
}


// -----------------------------------------------------------------------
// Key pair generation and public key encoding.
// -----------------------------------------------------------------------

static inline void p521_compute_public_key( // NOLINT(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays)
    const uint8_t private_scalar_be[66], // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    uint8_t public_key_uncompressed[133]) noexcept // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
{
    const P521Point pub = p521_to_affine(p521_scalar_mul_base(private_scalar_be));
    public_key_uncompressed[0] = 0x04U;
    fe521_to_bytes(pub.X, public_key_uncompressed + 1);   // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
    fe521_to_bytes(pub.Y, public_key_uncompressed + 67);  // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic,cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
}


}  // namespace arm_asm::detail
