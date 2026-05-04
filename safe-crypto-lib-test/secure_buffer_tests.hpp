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


TEST_F(SecureBufferTests, IterateMutableSecureBuffer) {
    SecureBuffer buf(3);
    buf[0] = 0x0A;
    buf[1] = 0x0B;
    buf[2] = 0x0C;

    CryptoByte sum{0};
    for (auto it = buf.begin(); it != buf.end(); ++it) { sum = static_cast<CryptoByte>(sum + *it); }
    EXPECT_EQ(sum, CryptoByte{0x0A + 0x0B + 0x0C});
}

TEST_F(SecureBufferTests, IterateConstSecureBuffer) {
    SecureBuffer buf(3);
    buf[0] = 0x01;
    buf[1] = 0x02;
    buf[2] = 0x04;

    const SecureBuffer& cbuf = buf;
    CryptoByte sum{0};
    for (auto it = cbuf.begin(); it != cbuf.end(); ++it) { sum = static_cast<CryptoByte>(sum + *it); }
    EXPECT_EQ(sum, CryptoByte{0x07});
}

TEST_F(SecureBufferTests, IterateMutableFixedSecureBuffer) {
    FixedSecureBuffer<3> buf;
    buf[0] = 0x10;
    buf[1] = 0x20;
    buf[2] = 0x30;

    CryptoByte sum{0};
    for (auto it = buf.begin(); it != buf.end(); ++it) { sum = static_cast<CryptoByte>(sum + *it); }
    EXPECT_EQ(sum, CryptoByte{0x60});
}

TEST_F(SecureBufferTests, IterateConstFixedSecureBuffer) {
    FixedSecureBuffer<3> buf;
    buf[0] = 0x11;
    buf[1] = 0x22;
    buf[2] = 0x33;

    const FixedSecureBuffer<3>& cbuf = buf;
    CryptoByte sum{0};
    for (auto it = cbuf.begin(); it != cbuf.end(); ++it) { sum = static_cast<CryptoByte>(sum + *it); }
    EXPECT_EQ(sum, CryptoByte{0x66});
}


TEST_F(SecureBufferTests, MoveConstructorTransfersData) {
    SecureBuffer src(3);
    src[0] = 0x11;
    src[1] = 0x22;
    src[2] = 0x33;
    SecureBuffer dst(std::move(src));
    EXPECT_EQ(dst.size(), 3U);
    EXPECT_EQ(dst[0], CryptoByte{0x11});
    EXPECT_EQ(dst[1], CryptoByte{0x22});
    EXPECT_EQ(dst[2], CryptoByte{0x33});
    EXPECT_TRUE(src.empty()); // NOLINT(bugprone-use-after-move,hicpp-invalid-access-moved)
}

TEST_F(SecureBufferTests, MoveAssignmentTransfersData) {
    SecureBuffer src(3);
    src[0] = 0xAA;
    src[1] = 0xBB;
    src[2] = 0xCC;
    SecureBuffer dst(2);
    dst[0] = 0x01;
    dst[1] = 0x02;
    dst = std::move(src);
    EXPECT_EQ(dst.size(), 3U);
    EXPECT_EQ(dst[0], CryptoByte{0xAA});
    EXPECT_EQ(dst[1], CryptoByte{0xBB});
    EXPECT_EQ(dst[2], CryptoByte{0xCC});
    EXPECT_TRUE(src.empty()); // NOLINT(bugprone-use-after-move,hicpp-invalid-access-moved)
}

TEST_F(SecureBufferTests, MoveAssignmentSelfAssignIsNoop) {
    SecureBuffer buf(2);
    buf[0] = 0x55;
    buf[1] = 0x66;
    // Self-assignment via reference cast must not corrupt state.
    buf = std::move(buf); // NOLINT(bugprone-use-after-move,hicpp-invalid-access-moved,clang-diagnostic-self-move)
    EXPECT_EQ(buf.size(), 2U);
}

TEST_F(SecureBufferTests, FixedMoveConstructorZeroesSource) {
    FixedSecureBuffer<4> src;
    src[0] = 0xDE;
    src[1] = 0xAD;
    src[2] = 0xBE;
    src[3] = 0xEF;
    const CryptoByte* src_ptr = src.data();
    FixedSecureBuffer<4> dst(std::move(src));
    EXPECT_EQ(dst[0], CryptoByte{0xDE});
    EXPECT_EQ(dst[3], CryptoByte{0xEF});
    // Source bytes must be zeroed after move.
    for (std::size_t i = 0; i < 4; ++i) {
        EXPECT_EQ(src_ptr[i], CryptoByte{0}); // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
    }
}

TEST_F(SecureBufferTests, FixedMoveAssignmentZeroesSourceAndDest) {
    FixedSecureBuffer<4> src;
    src[0] = 0x11;
    src[1] = 0x22;
    src[2] = 0x33;
    src[3] = 0x44;
    const CryptoByte* src_ptr = src.data();

    FixedSecureBuffer<4> dst;
    dst[0] = 0xAA;
    dst[1] = 0xBB;
    dst[2] = 0xCC;
    dst[3] = 0xDD;
    dst = std::move(src);

    EXPECT_EQ(dst[0], CryptoByte{0x11});
    EXPECT_EQ(dst[3], CryptoByte{0x44});
    // Source bytes must be zeroed after move.
    for (std::size_t i = 0; i < 4; ++i) {
        EXPECT_EQ(src_ptr[i], CryptoByte{0}); // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
    }
}

TEST_F(SecureBufferTests, FixedMoveAssignmentSelfAssignIsNoop) {
    FixedSecureBuffer<2> buf;
    buf[0] = 0x77;
    buf[1] = 0x88;
    buf = std::move(buf); // NOLINT(bugprone-use-after-move,hicpp-invalid-access-moved,clang-diagnostic-self-move)
    EXPECT_EQ(buf.size(), 2U);
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
