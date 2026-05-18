// SPDX-License-Identifier: Apache-2.0

#pragma once

// Compiler-portable [[gnu::target(...)]] string macros for AArch64.
//
// Apple Clang uses bare extension names ("aes", "neon", "sha2", "sha3").
// GCC and upstream Clang require a '+' prefix ("+aes", "+simd", "+sha2", "+sha3").
// NEON ("neon" / "+simd") is always-on for AArch64, so the attribute is a no-op
// at the ISA level, but must still be syntactically valid for the compiler.
//
// Usage:
//   [[gnu::target(ARM_TARGET_AES_NEON)]]   void f() { ... }
//   [[gnu::target(ARM_TARGET_NEON)]]        void g() { ... }
//   [[gnu::target(ARM_TARGET_SHA2_NEON)]]   void h() { ... }
//   [[gnu::target(ARM_TARGET_SHA3_NEON)]]   void k() { ... }

#ifdef __apple_build_version__
#  define ARM_TARGET_AES_NEON  "aes,neon"   // NOLINT(cppcoreguidelines-macro-usage)
#  define ARM_TARGET_NEON      "neon"        // NOLINT(cppcoreguidelines-macro-usage)
#  define ARM_TARGET_SHA2_NEON "sha2,neon"  // NOLINT(cppcoreguidelines-macro-usage)
#  define ARM_TARGET_SHA3_NEON "sha3,neon"  // NOLINT(cppcoreguidelines-macro-usage)
#else
#  define ARM_TARGET_AES_NEON  "+aes"   // NOLINT(cppcoreguidelines-macro-usage)
#  define ARM_TARGET_NEON      "+simd"  // NOLINT(cppcoreguidelines-macro-usage)
#  define ARM_TARGET_SHA2_NEON "+sha2"  // NOLINT(cppcoreguidelines-macro-usage)
#  define ARM_TARGET_SHA3_NEON "+sha3"  // NOLINT(cppcoreguidelines-macro-usage)
#endif
