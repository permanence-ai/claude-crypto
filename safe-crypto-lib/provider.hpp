// SPDX-License-Identifier: Apache-2.0

#pragma once

// Select the active backend at compile time via SAFE_CRYPTO_ACTIVE_PROVIDER.
// CMake propagates the matching compile definition through safe_crypto_lib's
// interface, so consumers do not need to set it manually.

#if defined(SAFE_CRYPTO_PROVIDER_ARM_ASM) && defined(SAFE_CRYPTO_ARM_ASM_AVAILABLE)
#  include "arm_asm_backend.hpp"
using DefaultProvider = ArmAsmBackend;
#elifdef SAFE_CRYPTO_PROVIDER_IA_ASM
#  include "ia_asm_backend.hpp"
using DefaultProvider = IaAsmBackend;
#elifdef SAFE_CRYPTO_PROVIDER_OPENSSL
#  include "openssl_backend.hpp"
using DefaultProvider = OpenSslBackend;
#else
#  include "psa_mbedtls_backend.hpp"
using DefaultProvider = RealPsaBackend;
#endif
