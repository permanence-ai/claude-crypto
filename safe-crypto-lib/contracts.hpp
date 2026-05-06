// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Permanence AI

#pragma once

// SAFE_CRYPTO_PRE(cond) — function precondition contract.
//
// Expands to [[pre: cond]] on GCC 15+ (C++26 contracts); no-op otherwise.
// Place between the parameter list (and cv/ref qualifiers) and the trailing
// return type:
//
//   auto f(std::size_t i) SAFE_CRYPTO_PRE(i < size_) -> T&;
//   auto g() const noexcept SAFE_CRYPTO_PRE(valid_) -> KeyId;
//
// SAFE_CRYPTO_CONTRACTS_ENFORCED is defined when contracts produce runtime
// checks (i.e. on the supported compiler with default enforcement mode).
// Tests can gate death-assertions on this macro.

#if defined(__GNUC__) && !defined(__clang__) && __GNUC__ >= 15
#  define SAFE_CRYPTO_PRE(cond) [[pre: cond]]
#  define SAFE_CRYPTO_CONTRACTS_ENFORCED
#else
#  define SAFE_CRYPTO_PRE(cond)
#endif
