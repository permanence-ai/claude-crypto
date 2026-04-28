/*
Copyright Permanence AI, 2026. All rights reserved.

*/

#pragma once

#include <cstddef>

#include <gtest/gtest.h>

#include "secure_buffer.hpp"


class SecureBufferTests : public ::testing::Test {};


TEST_F(SecureBufferTests, IndexOperatorReadsCorrectElement) {
    SecureBuffer buf(4);
    buf[0] = 0x01;
    buf[1] = 0x02;
    buf[2] = 0x03;
    buf[3] = 0x04;

    EXPECT_EQ(buf[0], 0x01);
    EXPECT_EQ(buf[3], 0x04);
}

TEST_F(SecureBufferTests, IndexOperatorConstReadsCorrectElement) {
    SecureBuffer buf(3);
    buf[0] = 0xAA;
    buf[2] = 0xBB;

    const SecureBuffer& cbuf = buf;
    EXPECT_EQ(cbuf[0], 0xAA);
    EXPECT_EQ(cbuf[2], 0xBB);
}

TEST_F(SecureBufferTests, FixedIndexOperatorReadsCorrectElement) {
    FixedSecureBuffer<4> buf;
    buf[0] = 0x11;
    buf[3] = 0x44;

    EXPECT_EQ(buf[0], 0x11);
    EXPECT_EQ(buf[3], 0x44);
}

TEST_F(SecureBufferTests, FixedIndexOperatorConstReadsCorrectElement) {
    FixedSecureBuffer<2> buf;
    buf[0] = 0xCC;
    buf[1] = 0xDD;

    const FixedSecureBuffer<2>& cbuf = buf;
    EXPECT_EQ(cbuf[0], 0xCC);
    EXPECT_EQ(cbuf[1], 0xDD);
}


#ifndef NDEBUG

TEST_F(SecureBufferTests, IndexOperatorOutOfBoundsDies) {
    SecureBuffer buf(4);
    ASSERT_DEATH((void)buf[4], "");
}

TEST_F(SecureBufferTests, IndexOperatorConstOutOfBoundsDies) {
    const SecureBuffer buf(4);
    ASSERT_DEATH((void)buf[4], "");
}

TEST_F(SecureBufferTests, IndexOperatorEmptyBufferDies) {
    SecureBuffer buf(0);
    ASSERT_DEATH((void)buf[0], "");
}

TEST_F(SecureBufferTests, FixedIndexOperatorOutOfBoundsDies) {
    FixedSecureBuffer<4> buf;
    ASSERT_DEATH((void)buf[4], "");
}

TEST_F(SecureBufferTests, FixedIndexOperatorConstOutOfBoundsDies) {
    const FixedSecureBuffer<4> buf;
    ASSERT_DEATH((void)buf[4], "");
}

#endif  // NDEBUG
