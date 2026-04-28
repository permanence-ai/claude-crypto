/*
Copyright Permanence AI, 2026. All rights reserved.

*/

#pragma once

// Select the active backend at compile time via CLAUDE_CRYPTO_PROVIDER.
// CMake sets this macro by passing -DCLAUDE_CRYPTO_PROVIDER_PSA_MBEDTLS (default)
// or -DCLAUDE_CRYPTO_PROVIDER_IA_ASM.

#if defined(CLAUDE_CRYPTO_PROVIDER_IA_ASM)
#  include "ia_asm_backend.hpp"
using DefaultProvider = IaAsmBackend;
#else
#  include "psa_mbedtls_backend.hpp"
using DefaultProvider = RealPsaBackend;
#endif
