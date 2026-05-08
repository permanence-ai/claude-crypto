// SPDX-License-Identifier: Apache-2.0

#pragma once

// Legacy forwarding header — includes the full provider abstraction layer plus
// the PSA/MbedTLS backend so that existing includes continue to work.
// New code should include crypto_provider.hpp and provider.hpp directly.

#include "crypto_provider.hpp"
#include "provider.hpp"
