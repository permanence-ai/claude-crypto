/*
Copyright Permanence AI, 2026. All rights reserved.

*/

#pragma once

#include <cstddef>

#include <gtest/gtest.h>

#include "contracts.hpp"
#include "secure_buffer.hpp"


class SecureBufferTests : public ::testing::Test {};


// NOLINTBEGIN(cppcoreguidelines-pro-bounds-avoid-unchecked-container-access, cppcoreguidelines-pro-bounds-constant-array-index)
TEST_F(SecureBufferTests, IndexOperatorReadsCorrectElement) {
    constexpr std::size_t buf_size = 4;
    constexpr CryptoByte  byte_a   = 0x01;
    constexpr CryptoByte  byte_b   = 0x04;
    SecureBuffer buf(buf_size);
    buf[0] = byte_a;
    buf[1] = 0x02;
    buf[2] = 0x03;
    buf[3] = byte_b;

    EXPECT_EQ(buf[0], byte_a);
    EXPECT_EQ(buf[3], byte_b);
}

TEST_F(SecureBufferTests, IndexOperatorConstReadsCorrectElement) {
    constexpr CryptoByte byte_a = 0xAA;
    constexpr CryptoByte byte_b = 0xBB;
    SecureBuffer buf(3);
    buf[0] = byte_a;
    buf[2] = byte_b;

    const SecureBuffer& cbuf = buf;
    EXPECT_EQ(cbuf[0], byte_a);
    EXPECT_EQ(cbuf[2], byte_b);
}

TEST_F(SecureBufferTests, FixedIndexOperatorReadsCorrectElement) {
    constexpr CryptoByte byte_a = 0x11;
    constexpr CryptoByte byte_b = 0x44;
    FixedSecureBuffer<4> buf;
    buf[0] = byte_a;
    buf[3] = byte_b;

    EXPECT_EQ(buf[0], byte_a);
    EXPECT_EQ(buf[3], byte_b);
}

TEST_F(SecureBufferTests, FixedIndexOperatorConstReadsCorrectElement) {
    constexpr CryptoByte byte_a = 0xCC;
    constexpr CryptoByte byte_b = 0xDD;
    FixedSecureBuffer<2> buf;
    buf[0] = byte_a;
    buf[1] = byte_b;

    const FixedSecureBuffer<2>& cbuf = buf;
    EXPECT_EQ(cbuf[0], byte_a);
    EXPECT_EQ(cbuf[1], byte_b);
}


#ifdef SAFE_CRYPTO_CONTRACTS_ENFORCED

TEST_F(SecureBufferTests, IndexOperatorOutOfBoundsDies) {
    constexpr std::size_t buf_size = 4;
    SecureBuffer buf(buf_size);
    ASSERT_DEATH((void)buf[buf_size], "");
}

TEST_F(SecureBufferTests, IndexOperatorConstOutOfBoundsDies) {
    constexpr std::size_t buf_size = 4;
    const SecureBuffer buf(buf_size);
    ASSERT_DEATH((void)buf[buf_size], "");
}

TEST_F(SecureBufferTests, IndexOperatorEmptyBufferDies) {
    SecureBuffer buf(0);
    ASSERT_DEATH((void)buf[0], "");
}

TEST_F(SecureBufferTests, FixedIndexOperatorOutOfBoundsDies) {
    constexpr std::size_t buf_size = 4;
    FixedSecureBuffer<buf_size> buf;
    ASSERT_DEATH((void)buf[buf_size], "");
}

TEST_F(SecureBufferTests, FixedIndexOperatorConstOutOfBoundsDies) {
    constexpr std::size_t buf_size = 4;
    const FixedSecureBuffer<buf_size> buf;
    ASSERT_DEATH((void)buf[buf_size], "");
}

#endif  // SAFE_CRYPTO_CONTRACTS_ENFORCED
// NOLINTEND(cppcoreguidelines-pro-bounds-avoid-unchecked-container-access, cppcoreguidelines-pro-bounds-constant-array-index)
