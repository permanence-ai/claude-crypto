/*
Copyright Permanence AI, 2026. All rights reserved.

*/

#pragma once

#include "secure_buffer.hpp"


[[nodiscard]]
auto sha384(const SecureBuffer& input) -> SecureBuffer;
