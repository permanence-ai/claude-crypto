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
