// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Permanence AI

#pragma once

// Replace liboqs's scalar xkcp Keccak with our ARM SHA3 intrinsic implementation
// for all SHA3 and SHAKE operations (both single-call and incremental APIs).
//
// Key design: absorb XORs directly into state (no intermediate copy buffer),
// matching xkcp's approach.  Only a squeeze_buf is needed and only in the
// squeeze phase.  This eliminates the extra memcpy pass that made the first
// implementation slower than xkcp.

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>

#include <oqs/sha3_ops.h>

#include "keccak.hpp"


namespace arm_asm::detail {

// ---------------------------------------------------------------------------
// Internal sponge context.
//
// Absorb phase: input bytes are XOR'd directly into state cast as uint8_t*.
//   pos tracks how many bytes of the current rate-block have been absorbed.
//   No intermediate copy buffer — one memory pass, same as xkcp.
//
// Squeeze phase: after finalize() the state holds the permuted output.
//   sq_buf holds a copy of the rate-many output bytes; sq_pos tracks how many
//   have been consumed so far.  When sq_pos reaches rate_bytes we permute
//   again and refill sq_buf.
// ---------------------------------------------------------------------------
struct ArmSha3Ctx {
    uint64_t state[25]{};       // Keccak-f[1600] state (200 bytes)
    uint8_t  sq_buf[168]{};     // squeeze output buffer (max rate = SHAKE-128 = 168 B)
    uint32_t rate_bytes{0};
    uint32_t pos{0};            // bytes absorbed into current block (absorb phase)
    uint32_t sq_pos{0};         // bytes consumed from sq_buf (squeeze phase)
    uint8_t  dsep{0};           // 0x06=SHA3, 0x1F=SHAKE
    bool     squeezing{false};

    void reset() noexcept {
        std::memset(state, 0, sizeof(state));
        pos        = 0;
        sq_pos     = 0;
        squeezing  = false;
    }

    // XOR input directly into state bytes; permute on block completion.
    [[gnu::target("sha3,neon")]]
    void absorb(const uint8_t* data, std::size_t len) noexcept {
        auto* sbytes = reinterpret_cast<uint8_t*>(state); // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast)
        while (len > 0) {
            const std::size_t space = rate_bytes - pos;
            const std::size_t take  = len < space ? len : space;
            for (std::size_t i = 0; i < take; ++i) {
                sbytes[pos + i] ^= data[i]; // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
            }
            pos  += static_cast<uint32_t>(take);
            data += take; // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
            len  -= take;
            if (pos == rate_bytes) {
                keccak_f1600(state);
                pos = 0;
            }
        }
    }

    // Apply SHA-3/SHAKE padding, permute, copy output block to sq_buf.
    [[gnu::target("sha3,neon")]]
    void finalize() noexcept {
        auto* sbytes = reinterpret_cast<uint8_t*>(state); // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast)
        sbytes[pos]              ^= dsep;
        sbytes[rate_bytes - 1U] ^= 0x80U;
        keccak_f1600(state);
        pos        = 0;
        sq_pos     = 0;
        squeezing  = true;
        std::memcpy(sq_buf, state, rate_bytes);
    }

    // Squeeze outlen bytes (SHAKE XOF — unlimited output).
    [[gnu::target("sha3,neon")]]
    void squeeze(uint8_t* output, std::size_t outlen) noexcept {
        while (outlen > 0) {
            if (sq_pos == rate_bytes) {
                keccak_f1600(state);
                std::memcpy(sq_buf, state, rate_bytes);
                sq_pos = 0;
            }
            const std::size_t avail = rate_bytes - sq_pos;
            const std::size_t take  = outlen < avail ? outlen : avail;
            std::memcpy(output, sq_buf + sq_pos, take);
            output += take; // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
            sq_pos += static_cast<uint32_t>(take);
            outlen -= take;
        }
    }

    // Fixed-output finish (SHA3 family).
    [[gnu::target("sha3,neon")]]
    void finish(uint8_t* output, std::size_t out_bytes) noexcept {
        finalize();
        std::memcpy(output, sq_buf, out_bytes);
    }
};

// ---------------------------------------------------------------------------
// Heap allocation helpers
// ---------------------------------------------------------------------------

[[nodiscard]]
static ArmSha3Ctx* ctx_alloc(uint32_t rate_bytes, uint8_t dsep) noexcept {
    auto* ctx = static_cast<ArmSha3Ctx*>(std::malloc(sizeof(ArmSha3Ctx))); // NOLINT(cppcoreguidelines-no-malloc,hicpp-no-malloc)
    if (ctx == nullptr) { return nullptr; }
    std::memset(ctx, 0, sizeof(ArmSha3Ctx));
    ctx->rate_bytes = rate_bytes;
    ctx->dsep       = dsep;
    return ctx;
}

static void ctx_free(ArmSha3Ctx* ctx) noexcept {
    if (ctx != nullptr) {
        std::memset(ctx, 0, sizeof(ArmSha3Ctx));
        std::free(ctx); // NOLINT(cppcoreguidelines-no-malloc,hicpp-no-malloc)
    }
}

static ArmSha3Ctx* as_ctx(void* p) noexcept {
    return static_cast<ArmSha3Ctx*>(p);
}

// ---------------------------------------------------------------------------
// Rate and domain-separator constants
// ---------------------------------------------------------------------------
static constexpr uint32_t k_shake128_rate = 168U;
static constexpr uint32_t k_shake256_rate = 136U;
static constexpr uint32_t k_sha3_256_rate = 136U;
static constexpr uint32_t k_sha3_384_rate = 104U;
static constexpr uint32_t k_sha3_512_rate =  72U;
static constexpr uint8_t  k_dsep_sha3     = 0x06U;
static constexpr uint8_t  k_dsep_shake    = 0x1FU;


// ---------------------------------------------------------------------------
// SHA3-256
// ---------------------------------------------------------------------------

[[gnu::target("sha3,neon")]]
static void cb_sha3_256(uint8_t* out, const uint8_t* in, std::size_t inlen) noexcept {
    ArmSha3Ctx ctx{};
    ctx.rate_bytes = k_sha3_256_rate; ctx.dsep = k_dsep_sha3;
    ctx.absorb(in, inlen);
    ctx.finish(out, 32U);
}
static void cb_sha3_256_inc_init(OQS_SHA3_sha3_256_inc_ctx* s) noexcept {
    s->ctx = ctx_alloc(k_sha3_256_rate, k_dsep_sha3);
}
static void cb_sha3_256_inc_absorb(OQS_SHA3_sha3_256_inc_ctx* s, const uint8_t* in, std::size_t inlen) noexcept {
    as_ctx(s->ctx)->absorb(in, inlen);
}
static void cb_sha3_256_inc_finalize(uint8_t* out, OQS_SHA3_sha3_256_inc_ctx* s) noexcept {
    as_ctx(s->ctx)->finish(out, 32U);
}
static void cb_sha3_256_inc_ctx_release(OQS_SHA3_sha3_256_inc_ctx* s) noexcept {
    ctx_free(as_ctx(s->ctx)); s->ctx = nullptr;
}
static void cb_sha3_256_inc_ctx_reset(OQS_SHA3_sha3_256_inc_ctx* s) noexcept {
    as_ctx(s->ctx)->reset();
}
static void cb_sha3_256_inc_ctx_clone(OQS_SHA3_sha3_256_inc_ctx* dst, const OQS_SHA3_sha3_256_inc_ctx* src) noexcept {
    *as_ctx(dst->ctx) = *as_ctx(src->ctx);
}


// ---------------------------------------------------------------------------
// SHA3-384
// ---------------------------------------------------------------------------

[[gnu::target("sha3,neon")]]
static void cb_sha3_384(uint8_t* out, const uint8_t* in, std::size_t inlen) noexcept {
    ArmSha3Ctx ctx{};
    ctx.rate_bytes = k_sha3_384_rate; ctx.dsep = k_dsep_sha3;
    ctx.absorb(in, inlen);
    ctx.finish(out, 48U);
}
static void cb_sha3_384_inc_init(OQS_SHA3_sha3_384_inc_ctx* s) noexcept {
    s->ctx = ctx_alloc(k_sha3_384_rate, k_dsep_sha3);
}
static void cb_sha3_384_inc_absorb(OQS_SHA3_sha3_384_inc_ctx* s, const uint8_t* in, std::size_t inlen) noexcept {
    as_ctx(s->ctx)->absorb(in, inlen);
}
static void cb_sha3_384_inc_finalize(uint8_t* out, OQS_SHA3_sha3_384_inc_ctx* s) noexcept {
    as_ctx(s->ctx)->finish(out, 48U);
}
static void cb_sha3_384_inc_ctx_release(OQS_SHA3_sha3_384_inc_ctx* s) noexcept {
    ctx_free(as_ctx(s->ctx)); s->ctx = nullptr;
}
static void cb_sha3_384_inc_ctx_reset(OQS_SHA3_sha3_384_inc_ctx* s) noexcept {
    as_ctx(s->ctx)->reset();
}
static void cb_sha3_384_inc_ctx_clone(OQS_SHA3_sha3_384_inc_ctx* dst, const OQS_SHA3_sha3_384_inc_ctx* src) noexcept {
    *as_ctx(dst->ctx) = *as_ctx(src->ctx);
}


// ---------------------------------------------------------------------------
// SHA3-512
// ---------------------------------------------------------------------------

[[gnu::target("sha3,neon")]]
static void cb_sha3_512(uint8_t* out, const uint8_t* in, std::size_t inlen) noexcept {
    ArmSha3Ctx ctx{};
    ctx.rate_bytes = k_sha3_512_rate; ctx.dsep = k_dsep_sha3;
    ctx.absorb(in, inlen);
    ctx.finish(out, 64U);
}
static void cb_sha3_512_inc_init(OQS_SHA3_sha3_512_inc_ctx* s) noexcept {
    s->ctx = ctx_alloc(k_sha3_512_rate, k_dsep_sha3);
}
static void cb_sha3_512_inc_absorb(OQS_SHA3_sha3_512_inc_ctx* s, const uint8_t* in, std::size_t inlen) noexcept {
    as_ctx(s->ctx)->absorb(in, inlen);
}
static void cb_sha3_512_inc_finalize(uint8_t* out, OQS_SHA3_sha3_512_inc_ctx* s) noexcept {
    as_ctx(s->ctx)->finish(out, 64U);
}
static void cb_sha3_512_inc_ctx_release(OQS_SHA3_sha3_512_inc_ctx* s) noexcept {
    ctx_free(as_ctx(s->ctx)); s->ctx = nullptr;
}
static void cb_sha3_512_inc_ctx_reset(OQS_SHA3_sha3_512_inc_ctx* s) noexcept {
    as_ctx(s->ctx)->reset();
}
static void cb_sha3_512_inc_ctx_clone(OQS_SHA3_sha3_512_inc_ctx* dst, const OQS_SHA3_sha3_512_inc_ctx* src) noexcept {
    *as_ctx(dst->ctx) = *as_ctx(src->ctx);
}


// ---------------------------------------------------------------------------
// SHAKE-128
// ---------------------------------------------------------------------------

[[gnu::target("sha3,neon")]]
static void cb_shake128(uint8_t* out, std::size_t outlen, const uint8_t* in, std::size_t inlen) noexcept {
    ArmSha3Ctx ctx{};
    ctx.rate_bytes = k_shake128_rate; ctx.dsep = k_dsep_shake;
    ctx.absorb(in, inlen);
    ctx.finalize();
    ctx.squeeze(out, outlen);
}
static void cb_shake128_inc_init(OQS_SHA3_shake128_inc_ctx* s) noexcept {
    s->ctx = ctx_alloc(k_shake128_rate, k_dsep_shake);
}
static void cb_shake128_inc_absorb(OQS_SHA3_shake128_inc_ctx* s, const uint8_t* in, std::size_t inlen) noexcept {
    as_ctx(s->ctx)->absorb(in, inlen);
}
static void cb_shake128_inc_finalize(OQS_SHA3_shake128_inc_ctx* s) noexcept {
    as_ctx(s->ctx)->finalize();
}
static void cb_shake128_inc_squeeze(uint8_t* out, std::size_t outlen, OQS_SHA3_shake128_inc_ctx* s) noexcept {
    as_ctx(s->ctx)->squeeze(out, outlen);
}
static void cb_shake128_inc_ctx_release(OQS_SHA3_shake128_inc_ctx* s) noexcept {
    ctx_free(as_ctx(s->ctx)); s->ctx = nullptr;
}
static void cb_shake128_inc_ctx_clone(OQS_SHA3_shake128_inc_ctx* dst, const OQS_SHA3_shake128_inc_ctx* src) noexcept {
    *as_ctx(dst->ctx) = *as_ctx(src->ctx);
}
static void cb_shake128_inc_ctx_reset(OQS_SHA3_shake128_inc_ctx* s) noexcept {
    as_ctx(s->ctx)->reset();
}


// ---------------------------------------------------------------------------
// SHAKE-256
// ---------------------------------------------------------------------------

[[gnu::target("sha3,neon")]]
static void cb_shake256(uint8_t* out, std::size_t outlen, const uint8_t* in, std::size_t inlen) noexcept {
    ArmSha3Ctx ctx{};
    ctx.rate_bytes = k_shake256_rate; ctx.dsep = k_dsep_shake;
    ctx.absorb(in, inlen);
    ctx.finalize();
    ctx.squeeze(out, outlen);
}
static void cb_shake256_inc_init(OQS_SHA3_shake256_inc_ctx* s) noexcept {
    s->ctx = ctx_alloc(k_shake256_rate, k_dsep_shake);
}
static void cb_shake256_inc_absorb(OQS_SHA3_shake256_inc_ctx* s, const uint8_t* in, std::size_t inlen) noexcept {
    as_ctx(s->ctx)->absorb(in, inlen);
}
static void cb_shake256_inc_finalize(OQS_SHA3_shake256_inc_ctx* s) noexcept {
    as_ctx(s->ctx)->finalize();
}
static void cb_shake256_inc_squeeze(uint8_t* out, std::size_t outlen, OQS_SHA3_shake256_inc_ctx* s) noexcept {
    as_ctx(s->ctx)->squeeze(out, outlen);
}
static void cb_shake256_inc_ctx_release(OQS_SHA3_shake256_inc_ctx* s) noexcept {
    ctx_free(as_ctx(s->ctx)); s->ctx = nullptr;
}
static void cb_shake256_inc_ctx_clone(OQS_SHA3_shake256_inc_ctx* dst, const OQS_SHA3_shake256_inc_ctx* src) noexcept {
    *as_ctx(dst->ctx) = *as_ctx(src->ctx);
}
static void cb_shake256_inc_ctx_reset(OQS_SHA3_shake256_inc_ctx* s) noexcept {
    as_ctx(s->ctx)->reset();
}


// ---------------------------------------------------------------------------
// Callback table and install function
// ---------------------------------------------------------------------------

// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables)
static OQS_SHA3_callbacks g_arm_sha3_callbacks = {
    cb_sha3_256,
    cb_sha3_256_inc_init,
    cb_sha3_256_inc_absorb,
    cb_sha3_256_inc_finalize,
    cb_sha3_256_inc_ctx_release,
    cb_sha3_256_inc_ctx_reset,
    cb_sha3_256_inc_ctx_clone,

    cb_sha3_384,
    cb_sha3_384_inc_init,
    cb_sha3_384_inc_absorb,
    cb_sha3_384_inc_finalize,
    cb_sha3_384_inc_ctx_release,
    cb_sha3_384_inc_ctx_reset,
    cb_sha3_384_inc_ctx_clone,

    cb_sha3_512,
    cb_sha3_512_inc_init,
    cb_sha3_512_inc_absorb,
    cb_sha3_512_inc_finalize,
    cb_sha3_512_inc_ctx_release,
    cb_sha3_512_inc_ctx_reset,
    cb_sha3_512_inc_ctx_clone,

    cb_shake128,
    cb_shake128_inc_init,
    cb_shake128_inc_absorb,
    cb_shake128_inc_finalize,
    cb_shake128_inc_squeeze,
    cb_shake128_inc_ctx_release,
    cb_shake128_inc_ctx_clone,
    cb_shake128_inc_ctx_reset,

    cb_shake256,
    cb_shake256_inc_init,
    cb_shake256_inc_absorb,
    cb_shake256_inc_finalize,
    cb_shake256_inc_squeeze,
    cb_shake256_inc_ctx_release,
    cb_shake256_inc_ctx_clone,
    cb_shake256_inc_ctx_reset,
};

inline void install_arm_sha3_callbacks() noexcept {
    OQS_SHA3_set_callbacks(&g_arm_sha3_callbacks);
}

}  // namespace arm_asm::detail
