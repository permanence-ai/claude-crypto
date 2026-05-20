// SPDX-License-Identifier: Apache-2.0

#pragma once

// Re-export CryptoByte from the shared safe-crypto-lib header so every IA-ASM
// detail header can include only this file instead of navigating back to the
// library root.

#include "../../safe-crypto-lib/defs.hpp"

// Activate the full IA-ASM ISA for every TU that includes this header.
// Per-function [[gnu::target(...)]] attributes are unreliable in header-only
// TUs under GCC — the pragma form is the documented reliable mechanism.
#ifdef __GNUC__
#pragma GCC target("aes,sha,pclmul,ssse3,sse4.1")
#endif

// IA_TARGET(features): per-function ISA annotation.
// On GCC/Clang this expands to [[gnu::target(features)]], enabling the listed
// ISA extensions for that function even when the TU baseline is lower.
// On MSVC the whole-TU /arch:AVX2 flag (set in CMake) already enables all
// required intrinsics, so the per-function attribute is a no-op.
#ifdef _MSC_VER
#  define IA_TARGET(...) /* MSVC: ISA enabled project-wide via /arch:AVX2 */
#else
#  define IA_TARGET(...) [[gnu::target(__VA_ARGS__)]]
#endif
