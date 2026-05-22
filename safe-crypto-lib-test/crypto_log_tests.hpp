// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <string>
#include <string_view>
#include <vector>

#include <gtest/gtest.h>

#include "crypto_log.hpp"
#include "digests.hpp"
#include "test_utils.hpp"


class CryptoLogTests : public ::testing::Test {
protected:
    void TearDown() override {
        // Always reset to silent state after each test so the global singleton
        // does not bleed captured state into subsequent tests.
        crypto_set_log_sink(nullptr);
    }
};


// ---------------------------------------------------------------------------
// crypto_set_log_sink / crypto_log_enabled / crypto_log
// ---------------------------------------------------------------------------

TEST_F(CryptoLogTests, DefaultStateIsOff) {
    EXPECT_FALSE(crypto_log_enabled(CryptoLogLevel::Debug));
    EXPECT_FALSE(crypto_log_enabled(CryptoLogLevel::Info));
    EXPECT_FALSE(crypto_log_enabled(CryptoLogLevel::Warn));
    EXPECT_FALSE(crypto_log_enabled(CryptoLogLevel::Error));
}

TEST_F(CryptoLogTests, EnabledAfterSinkRegistered) {
    crypto_set_log_sink([](CryptoLogLevel, std::string_view) {}, CryptoLogLevel::Debug);
    EXPECT_TRUE(crypto_log_enabled(CryptoLogLevel::Debug));
    EXPECT_TRUE(crypto_log_enabled(CryptoLogLevel::Error));
}

TEST_F(CryptoLogTests, ThresholdFiltersLowerLevels) {
    crypto_set_log_sink([](CryptoLogLevel, std::string_view) {}, CryptoLogLevel::Warn);
    EXPECT_FALSE(crypto_log_enabled(CryptoLogLevel::Debug));
    EXPECT_FALSE(crypto_log_enabled(CryptoLogLevel::Info));
    EXPECT_TRUE(crypto_log_enabled(CryptoLogLevel::Warn));
    EXPECT_TRUE(crypto_log_enabled(CryptoLogLevel::Error));
}

TEST_F(CryptoLogTests, NullptrSinkDisablesLogging) {
    crypto_set_log_sink([](CryptoLogLevel, std::string_view) {}, CryptoLogLevel::Debug);
    ASSERT_TRUE(crypto_log_enabled(CryptoLogLevel::Debug));

    crypto_set_log_sink(nullptr);
    EXPECT_FALSE(crypto_log_enabled(CryptoLogLevel::Debug));
}

TEST_F(CryptoLogTests, SinkReceivesMessages) {
    struct Entry { CryptoLogLevel level; std::string msg; };
    std::vector<Entry> captured;

    crypto_set_log_sink([&captured](CryptoLogLevel lvl, std::string_view m) {
        captured.push_back({lvl, std::string(m)});
    }, CryptoLogLevel::Debug);

    crypto_log(CryptoLogLevel::Debug, "hello debug");
    crypto_log(CryptoLogLevel::Info,  "hello info");
    crypto_log(CryptoLogLevel::Error, "hello error");

    ASSERT_EQ(captured.size(), 3U);
    EXPECT_EQ(captured[0].level, CryptoLogLevel::Debug);
    EXPECT_EQ(captured[0].msg,   "hello debug");
    EXPECT_EQ(captured[1].level, CryptoLogLevel::Info);
    EXPECT_EQ(captured[2].level, CryptoLogLevel::Error);
}

TEST_F(CryptoLogTests, MessagesAtOrAboveThresholdDelivered) {
    std::vector<CryptoLogLevel> levels;
    crypto_set_log_sink([&levels](CryptoLogLevel lvl, std::string_view) {
        levels.push_back(lvl);
    }, CryptoLogLevel::Warn);

    crypto_log(CryptoLogLevel::Debug, "filtered");
    crypto_log(CryptoLogLevel::Info,  "filtered");
    crypto_log(CryptoLogLevel::Warn,  "delivered");
    crypto_log(CryptoLogLevel::Error, "delivered");

    ASSERT_EQ(levels.size(), 2U);
    EXPECT_EQ(levels[0], CryptoLogLevel::Warn);
    EXPECT_EQ(levels[1], CryptoLogLevel::Error);
}

TEST_F(CryptoLogTests, NoMessagesWhenSinkIsNull) {
    bool called = false;
    crypto_set_log_sink([&called](CryptoLogLevel, std::string_view) { called = true; },
                        CryptoLogLevel::Debug);
    crypto_set_log_sink(nullptr);

    crypto_log(CryptoLogLevel::Error, "should not arrive");
    EXPECT_FALSE(called);
}

TEST_F(CryptoLogTests, MsgHelperFormatsOneKv) {
    const auto s = crypto_log_detail::msg("op", "input", 64U);
    EXPECT_NE(s.find("op"),    std::string::npos);
    EXPECT_NE(s.find("input"), std::string::npos);
    EXPECT_NE(s.find("64"),    std::string::npos);
    EXPECT_NE(s.find("bytes"), std::string::npos);
}

TEST_F(CryptoLogTests, MsgHelperFormatsTwoKv) {
    const auto s = crypto_log_detail::msg("aead", "plaintext", 100U, "aad", 16U);
    EXPECT_NE(s.find("plaintext"), std::string::npos);
    EXPECT_NE(s.find("100"),       std::string::npos);
    EXPECT_NE(s.find("aad"),       std::string::npos);
    EXPECT_NE(s.find("16"),        std::string::npos);
}

TEST_F(CryptoLogTests, MsgHelperFormatsThreeKv) {
    const auto s = crypto_log_detail::msg("op", "a", 1U, "b", 2U, "c", 3U);
    EXPECT_NE(s.find("a"), std::string::npos);
    EXPECT_NE(s.find("b"), std::string::npos);
    EXPECT_NE(s.find("c"), std::string::npos);
}

// ---------------------------------------------------------------------------
// Integration: library operations emit expected log events
// ---------------------------------------------------------------------------

TEST_F(CryptoLogTests, ShaEmitsDebugEntryAndSuccess) {
    struct Entry { CryptoLogLevel level; std::string msg; };
    std::vector<Entry> captured;

    crypto_set_log_sink([&captured](CryptoLogLevel lvl, std::string_view m) {
        captured.push_back({lvl, std::string(m)});
    }, CryptoLogLevel::Debug);

    const auto input = make_random_secure_buffer(32);
    const auto result = sha<ShaVariant::Sha256>(input);
    ASSERT_TRUE(result.has_value());

    ASSERT_GE(captured.size(), 2U);
    EXPECT_NE(captured[0].msg.find("sha"),   std::string::npos);
    EXPECT_NE(captured[0].msg.find("input"), std::string::npos);
    EXPECT_EQ(captured[0].level, CryptoLogLevel::Debug);
    const auto& success = captured.back();
    EXPECT_NE(success.msg.find("sha"),    std::string::npos);
    EXPECT_NE(success.msg.find("digest"), std::string::npos);
    EXPECT_EQ(success.level, CryptoLogLevel::Debug);
}

TEST_F(CryptoLogTests, NoLibraryLogEventsWhenSinkIsNull) {
    bool called = false;
    crypto_set_log_sink([&called](CryptoLogLevel, std::string_view) { called = true; },
                        CryptoLogLevel::Debug);
    crypto_set_log_sink(nullptr);

    const auto input = make_random_secure_buffer(32);
    const auto result = sha<ShaVariant::Sha256>(input);
    ASSERT_TRUE(result.has_value());
    EXPECT_FALSE(called);
}

TEST_F(CryptoLogTests, ErrorLevelOnlyDoesNotReceiveDebugFromLibrary) {
    std::vector<CryptoLogLevel> levels;
    crypto_set_log_sink([&levels](CryptoLogLevel lvl, std::string_view) {
        levels.push_back(lvl);
    }, CryptoLogLevel::Error);

    const auto input = make_random_secure_buffer(32);
    const auto result = sha<ShaVariant::Sha256>(input);
    ASSERT_TRUE(result.has_value());

    EXPECT_TRUE(levels.empty());
}
