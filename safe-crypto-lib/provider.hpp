/*
Copyright Permanence AI, 2026. All rights reserved.

*/

#pragma once

// Select the active backend at compile time via SAFE_CRYPTO_ACTIVE_PROVIDER.
// CMake propagates the matching compile definition (SAFE_CRYPTO_PROVIDER_IA_ASM
// or nothing for the default PSA_MBEDTLS) through safe_crypto_lib's interface,
// so consumers do not need to set it manually.

#if defined(SAFE_CRYPTO_PROVIDER_IA_ASM)
#  include "ia_asm_backend.hpp"
using DefaultProvider = IaAsmBackend;
#else
#  include "psa_mbedtls_backend.hpp"
using DefaultProvider = RealPsaBackend;
#endif
