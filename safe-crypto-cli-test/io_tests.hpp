// SPDX-License-Identifier: Apache-2.0

#pragma once

// Tests for every input/output spec combination across all subcommands.
// Combinations exercised per command:
//   (1) base64 input  → stdout (base64)       [covered by existing tests]
//   (2) base64 input  → file output
//   (3) file input    → stdout (base64)
//   (4) file input    → file output
//   (5) mixed: some params base64, others file, in one invocation

#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

#include <sys/stat.h>
#include <unistd.h>

#include <gtest/gtest.h>

#include "cli_test_runner.hpp"


namespace scli_test {

class IoTests : public ::testing::Test {
protected:
    static auto scli() -> const std::string& {
        static const std::string path{SCLI_PATH};  // NOLINT(cppcoreguidelines-pro-bounds-array-to-pointer-decay,hicpp-no-array-decay)
        return path;
    }

    // "hello" raw bytes as base64.
    static constexpr const char* kHelloB64    = "aGVsbG8=";
    // "hello world" raw bytes as base64.
    static constexpr const char* kHelloWorldB64 = "aGVsbG8gd29ybGQ=";
    // 32-byte all-zeros key.
    static constexpr const char* kKeyB64 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

    void TearDown() override {
        for (const auto& p : tmp_files_) {
            std::filesystem::remove(p);
        }
        for (const auto& d : tmp_dirs_) {
            std::filesystem::remove_all(d);
        }
    }

    // Register a temp file path for cleanup and return it.
    auto tmp(const std::string& name) -> std::string {
        const std::string path = (std::filesystem::temp_directory_path() / name).string();
        tmp_files_.push_back(path);
        return path;
    }

    // Write base64-decoded bytes to a named temp file; registers for cleanup.
    auto tmp_b64(const std::string& name, const std::string& b64) -> std::string {
        const std::string path = write_temp_file_b64(name, b64);
        tmp_files_.push_back(path);
        return path;
    }

    // Register a temp directory for cleanup (via remove_all) and return it.
    auto tmp_dir(const std::string& name) -> std::filesystem::path {
        const auto path = std::filesystem::temp_directory_path() / name;
        tmp_dirs_.push_back(path);
        return path;
    }

    std::vector<std::string> tmp_files_;
    std::vector<std::filesystem::path> tmp_dirs_;
};


// ─── digest ──────────────────────────────────────────────────────────────────

TEST_F(IoTests, Digest_Base64Input_FileOutput) {
    const std::string out_path = tmp("io_digest_out.bin");
    const auto r = run_scli(scli(),
        {"digest", "--algo", "sha256", "--input", "base64:" + std::string(kHelloB64),
         "--output", out_path});
    EXPECT_EQ(r.exit_code, 0);
    // Output file should contain 32 raw bytes.
    EXPECT_EQ(std::filesystem::file_size(out_path), 32U);
}

TEST_F(IoTests, Digest_FileInput_StdoutOutput) {
    const std::string in_path = tmp_b64("io_digest_in.bin", kHelloB64);
    const auto r = run_scli(scli(),
        {"digest", "--algo", "sha256", "--input", in_path});
    EXPECT_EQ(r.exit_code, 0);
    // SHA-256("hello") in base64.
    EXPECT_EQ(r.stdout_text, "LPJNul+wow4m6DsqxbninhsWHlwfp0JecwQzYpOLmCQ=");
}

TEST_F(IoTests, Digest_FileInput_FileOutput) {
    const std::string in_path  = tmp_b64("io_digest_in2.bin", kHelloB64);
    const std::string out_path = tmp("io_digest_out2.bin");
    const auto r = run_scli(scli(),
        {"digest", "--algo", "sha256", "--input", in_path, "--output", out_path});
    EXPECT_EQ(r.exit_code, 0);
    EXPECT_EQ(std::filesystem::file_size(out_path), 32U);
}


// ─── mac ─────────────────────────────────────────────────────────────────────

TEST_F(IoTests, Mac_Base64Input_FileOutput) {
    const std::string out_path = tmp("io_mac_out.bin");
    const auto r = run_scli(scli(),
        {"mac", "--algo", "sha256",
         "--key", "base64:" + std::string(kKeyB64),
         "--input", "base64:" + std::string(kHelloB64),
         "--output", out_path});
    EXPECT_EQ(r.exit_code, 0);
    // HMAC-SHA-256 output is 32 bytes.
    EXPECT_EQ(std::filesystem::file_size(out_path), 32U);
}

TEST_F(IoTests, Mac_FileKey_Base64Input_StdoutOutput) {
    // Key from file, message from base64.
    const std::string key_path = tmp_b64("io_mac_key.bin", kKeyB64);
    const auto r = run_scli(scli(),
        {"mac", "--algo", "sha256",
         "--key", key_path,
         "--input", "base64:" + std::string(kHelloB64)});
    EXPECT_EQ(r.exit_code, 0);
    EXPECT_FALSE(r.stdout_text.empty());
}

TEST_F(IoTests, Mac_Base64Key_FileInput_StdoutOutput) {
    // Key from base64, message from file.
    const std::string msg_path = tmp_b64("io_mac_msg.bin", kHelloB64);
    const auto r = run_scli(scli(),
        {"mac", "--algo", "sha256",
         "--key", "base64:" + std::string(kKeyB64),
         "--input", msg_path});
    EXPECT_EQ(r.exit_code, 0);
    EXPECT_FALSE(r.stdout_text.empty());
}

TEST_F(IoTests, Mac_FileKey_FileInput_FileOutput) {
    const std::string key_path = tmp_b64("io_mac_key2.bin", kKeyB64);
    const std::string msg_path = tmp_b64("io_mac_msg2.bin", kHelloB64);
    const std::string out_path = tmp("io_mac_out2.bin");
    const auto r = run_scli(scli(),
        {"mac", "--algo", "sha256",
         "--key", key_path,
         "--input", msg_path,
         "--output", out_path});
    EXPECT_EQ(r.exit_code, 0);
    EXPECT_EQ(std::filesystem::file_size(out_path), 32U);
}

TEST_F(IoTests, Mac_MixedInputs_VerifyFromFile) {
    // Generate MAC with base64 inputs, write to file, then verify reading
    // both message and MAC from files.
    const std::string mac_path = tmp("io_mac_verify.bin");
    const auto gen = run_scli(scli(),
        {"mac", "--algo", "sha256",
         "--key", "base64:" + std::string(kKeyB64),
         "--input", "base64:" + std::string(kHelloB64),
         "--output", mac_path});
    ASSERT_EQ(gen.exit_code, 0);

    const std::string msg_path = tmp_b64("io_mac_msg3.bin", kHelloB64);

    // Verify: key from base64 cmd line, message from file, MAC from file.
    const auto verify = run_scli(scli(),
        {"mac", "--algo", "sha256",
         "--key", "base64:" + std::string(kKeyB64),
         "--input", msg_path,
         "--verify", mac_path});
    EXPECT_EQ(verify.exit_code, 0);
}


// ─── aead ─────────────────────────────────────────────────────────────────────

TEST_F(IoTests, Aead_Base64Input_FileOutput_RoundTrip) {
    const std::string ct_path  = tmp("io_aead_ct.bin");
    const std::string key_spec = "base64:" + std::string(kKeyB64);

    // Encrypt: base64 plaintext → ciphertext file.
    const auto enc = run_scli(scli(),
        {"aead", "--algo", "aes256-gcm", "--op", "encrypt",
         "--key", key_spec,
         "--input", "base64:" + std::string(kHelloWorldB64),
         "--output", ct_path});
    ASSERT_EQ(enc.exit_code, 0);

    // Decrypt: ciphertext file → base64 stdout.
    const auto dec = run_scli(scli(),
        {"aead", "--algo", "aes256-gcm", "--op", "decrypt",
         "--key", key_spec,
         "--input", ct_path});
    EXPECT_EQ(dec.exit_code, 0);
    EXPECT_EQ(dec.stdout_text, kHelloWorldB64);
}

TEST_F(IoTests, Aead_FileInput_StdoutOutput_RoundTrip) {
    const std::string pt_path = tmp_b64("io_aead_pt.bin", kHelloWorldB64);
    const std::string key_spec = "base64:" + std::string(kKeyB64);

    // Encrypt: plaintext file → base64 stdout.
    const auto enc = run_scli(scli(),
        {"aead", "--algo", "aes256-gcm", "--op", "encrypt",
         "--key", key_spec,
         "--input", pt_path});
    ASSERT_EQ(enc.exit_code, 0);

    // Decrypt: base64 ciphertext from stdout → base64 stdout.
    const auto dec = run_scli(scli(),
        {"aead", "--algo", "aes256-gcm", "--op", "decrypt",
         "--key", key_spec,
         "--input", "base64:" + enc.stdout_text});
    EXPECT_EQ(dec.exit_code, 0);
    EXPECT_EQ(dec.stdout_text, kHelloWorldB64);
}

TEST_F(IoTests, Aead_FileInput_FileOutput_RoundTrip) {
    const std::string pt_path  = tmp_b64("io_aead_pt2.bin", kHelloWorldB64);
    const std::string ct_path  = tmp("io_aead_ct2.bin");
    const std::string pt2_path = tmp("io_aead_pt2_dec.bin");
    const std::string key_spec = "base64:" + std::string(kKeyB64);

    const auto enc = run_scli(scli(),
        {"aead", "--algo", "aes256-gcm", "--op", "encrypt",
         "--key", key_spec,
         "--input", pt_path,
         "--output", ct_path});
    ASSERT_EQ(enc.exit_code, 0);

    const auto dec = run_scli(scli(),
        {"aead", "--algo", "aes256-gcm", "--op", "decrypt",
         "--key", key_spec,
         "--input", ct_path,
         "--output", pt2_path});
    EXPECT_EQ(dec.exit_code, 0);

    // Decrypted file must equal original plaintext.
    const auto pt_bytes  = read_file_bytes(pt_path);
    const auto pt2_bytes = read_file_bytes(pt2_path);
    EXPECT_EQ(pt_bytes, pt2_bytes);
}

TEST_F(IoTests, Aead_MixedIO_KeyFile_PlaintextB64_CiphertextFile) {
    // Key from file, plaintext from cmd line (base64), ciphertext to file —
    // then decrypt with key from cmd line, ciphertext from file.
    const std::string key_path = tmp_b64("io_aead_key.bin", kKeyB64);
    const std::string ct_path  = tmp("io_aead_mixed_ct.bin");

    const auto enc = run_scli(scli(),
        {"aead", "--algo", "aes256-gcm", "--op", "encrypt",
         "--key", key_path,
         "--input", "base64:" + std::string(kHelloWorldB64),
         "--output", ct_path});
    ASSERT_EQ(enc.exit_code, 0);

    const auto dec = run_scli(scli(),
        {"aead", "--algo", "aes256-gcm", "--op", "decrypt",
         "--key", "base64:" + std::string(kKeyB64),
         "--input", ct_path});
    EXPECT_EQ(dec.exit_code, 0);
    EXPECT_EQ(dec.stdout_text, kHelloWorldB64);
}

TEST_F(IoTests, Aead_MixedIO_AadFromFile) {
    // Encrypt with AAD from a file, then decrypt with AAD from base64.
    const std::string aad_path = tmp_b64("io_aead_aad.bin", "bXkgYWFk");  // "my aad"
    const std::string key_spec = "base64:" + std::string(kKeyB64);

    const auto enc = run_scli(scli(),
        {"aead", "--algo", "aes256-gcm", "--op", "encrypt",
         "--key", key_spec,
         "--input", "base64:" + std::string(kHelloWorldB64),
         "--aad", aad_path});
    ASSERT_EQ(enc.exit_code, 0);

    const auto dec = run_scli(scli(),
        {"aead", "--algo", "aes256-gcm", "--op", "decrypt",
         "--key", key_spec,
         "--input", "base64:" + enc.stdout_text,
         "--aad", "base64:bXkgYWFk"});
    EXPECT_EQ(dec.exit_code, 0);
    EXPECT_EQ(dec.stdout_text, kHelloWorldB64);
}


// ─── random ───────────────────────────────────────────────────────────────────

TEST_F(IoTests, Random_FileOutput) {
    const std::string out_path = tmp("io_random_out.bin");
    const auto r = run_scli(scli(), {"random", "--length", "32", "--output", out_path});
    EXPECT_EQ(r.exit_code, 0);
    EXPECT_EQ(std::filesystem::file_size(out_path), 32U);
}

TEST_F(IoTests, Random_FileOutput_ContentIsRandom) {
    const std::string p1 = tmp("io_random_a.bin");
    const std::string p2 = tmp("io_random_b.bin");
    const auto r1 = run_scli(scli(), {"random", "--length", "32", "--output", p1});
    const auto r2 = run_scli(scli(), {"random", "--length", "32", "--output", p2});
    ASSERT_EQ(r1.exit_code, 0);
    ASSERT_EQ(r2.exit_code, 0);
    EXPECT_NE(read_file_bytes(p1), read_file_bytes(p2));
}


// ─── secret file permissions ─────────────────────────────────────────────────

TEST_F(IoTests, SecretOutput_PrivateKeyFile_HasMode0600) {
    const std::string priv_path = tmp("io_perm_priv.der");
    const std::string pub_path  = tmp("io_perm_pub.der");

    // Generate an ECDSA key pair; private key must land at mode 0600.
    const auto r = run_scli(scli(),
        {"ecdsa", "keygen", "--curve", "p256",
         "--out-private", priv_path, "--out-public", pub_path});
    ASSERT_EQ(r.exit_code, 0);

    struct stat st{};
    ASSERT_EQ(::stat(priv_path.c_str(), &st), 0);
    EXPECT_EQ(st.st_mode & 0777U, 0600U);  // NOLINT(cppcoreguidelines-avoid-magic-numbers)
}

TEST_F(IoTests, SecretOutput_PublicKeyFile_HasDefaultUmaskMode) {
    const std::string priv_path = tmp("io_perm_priv2.der");
    const std::string pub_path  = tmp("io_perm_pub2.der");

    const auto r = run_scli(scli(),
        {"ecdsa", "keygen", "--curve", "p256",
         "--out-private", priv_path, "--out-public", pub_path});
    ASSERT_EQ(r.exit_code, 0);

    // Public key uses write_output (std::ofstream), so mode is set by umask —
    // just verify the file is readable (not locked down to 0000).
    struct stat st{};
    ASSERT_EQ(::stat(pub_path.c_str(), &st), 0);
    EXPECT_NE(st.st_mode & S_IRUSR, 0U);  // NOLINT(hicpp-signed-bitwise)
}

TEST_F(IoTests, SecretOutput_RejectsExistingFile) {
    const std::string priv_path = tmp("io_perm_exist.der");
    const std::string pub_path  = tmp("io_perm_exist_pub.der");

    // First keygen creates the file.
    const auto r1 = run_scli(scli(),
        {"ecdsa", "keygen", "--curve", "p256",
         "--out-private", priv_path, "--out-public", pub_path});
    ASSERT_EQ(r1.exit_code, 0);

    // Second keygen must fail: private key file already exists.
    // Remove pub so it does not interfere.
    std::filesystem::remove(pub_path);
    const std::string pub_path2 = tmp("io_perm_exist_pub2.der");
    const auto r2 = run_scli(scli(),
        {"ecdsa", "keygen", "--curve", "p256",
         "--out-private", priv_path, "--out-public", pub_path2});
    EXPECT_NE(r2.exit_code, 0);
}

TEST_F(IoTests, SecretOutput_RejectsSymlink) {
    const std::string real_path = tmp("io_perm_target.der");
    const std::string link_path = tmp("io_perm_link.der");
    const std::string pub_path  = tmp("io_perm_link_pub.der");

    // Create an empty file and a symlink pointing to it.
    { std::ofstream f(real_path); }
    ::symlink(real_path.c_str(), link_path.c_str());

    // Attempt to write private key through the symlink must fail.
    const auto r = run_scli(scli(),
        {"ecdsa", "keygen", "--curve", "p256",
         "--out-private", link_path, "--out-public", pub_path});
    EXPECT_NE(r.exit_code, 0);

    std::filesystem::remove(real_path);
}

TEST_F(IoTests, SecretOutput_KdfDeriveOutputFile_HasMode0600) {
    const std::string out_path = tmp("io_perm_kdf_derive.bin");
    // 64-zero-byte IKM (base64) for a 32-byte output.
    const auto r = run_scli(scli(),
        {"kdf", "derive", "--length", "32",
         "--ikm", "base64:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
         "--output", out_path});
    ASSERT_EQ(r.exit_code, 0);

    struct stat st{};
    ASSERT_EQ(::stat(out_path.c_str(), &st), 0);
    EXPECT_EQ(st.st_mode & 0777U, 0600U);  // NOLINT(cppcoreguidelines-avoid-magic-numbers)
}

TEST_F(IoTests, SecretOutput_KdfDeriveOutputFile_RejectsExistingPath) {
    const std::string out_path = tmp("io_perm_kdf_derive_exist.bin");
    const std::string ikm_spec =
        "base64:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    // First derive creates the file.
    const auto r1 = run_scli(scli(),
        {"kdf", "derive", "--length", "32", "--ikm", ikm_spec, "--output", out_path});
    ASSERT_EQ(r1.exit_code, 0);

    // Second derive must fail: output file already exists.
    const auto r2 = run_scli(scli(),
        {"kdf", "derive", "--length", "32", "--ikm", ikm_spec, "--output", out_path});
    EXPECT_NE(r2.exit_code, 0);
}


// ─── ecdsa ────────────────────────────────────────────────────────────────────

TEST_F(IoTests, Ecdsa_Base64Key_FileInput_FileOutput_RoundTrip) {
    // keygen to files, sign with message from file, write sig to file, verify.
    const std::string priv_path = tmp("io_ecdsa_priv.der");
    const std::string pub_path  = tmp("io_ecdsa_pub.der");
    const std::string msg_path  = tmp_b64("io_ecdsa_msg.bin", kHelloWorldB64);
    const std::string sig_path  = tmp("io_ecdsa_sig.bin");

    const auto kg = run_scli(scli(),
        {"ecdsa", "keygen", "--curve", "p256",
         "--out-private", priv_path, "--out-public", pub_path});
    ASSERT_EQ(kg.exit_code, 0);

    // Sign: key from file, message from file, signature to file.
    const auto sig = run_scli(scli(),
        {"ecdsa", "sign", "--curve", "p256",
         "--key", priv_path, "--input", msg_path, "--output", sig_path});
    ASSERT_EQ(sig.exit_code, 0);

    // Verify: key from file, message from base64 cmd line, signature from file.
    const auto verify = run_scli(scli(),
        {"ecdsa", "verify", "--curve", "p256",
         "--key", pub_path,
         "--input", "base64:" + std::string(kHelloWorldB64),
         "--signature", sig_path});
    EXPECT_EQ(verify.exit_code, 0);
}

// ─── bounded input ────────────────────────────────────────────────────────────

// Helper: write `count` bytes (all zeros) to a temp file.
static auto write_zero_file(const std::string& path, std::size_t count) -> void {
    std::ofstream f(path, std::ios::binary);
    std::vector<char> zeros(count, '\0');
    f.write(zeros.data(), static_cast<std::streamsize>(count));
}

// Keys are capped at 64 KiB (65536 bytes).  A 65537-byte "key" file must be rejected.
TEST_F(IoTests, BoundedInput_OversizedKeyFile_DigestMacRejectsWithNonZero) {
    const std::string big_key = tmp("io_bounded_key.bin");
    write_zero_file(big_key, 65537U);

    // mac --key with a 65537-byte file must fail.
    const auto r = run_scli(scli(),
        {"mac", "--algo", "sha256", "--key", big_key,
         "--input", "base64:" + std::string(kHelloB64)});
    EXPECT_NE(r.exit_code, 0);
}

// Messages are capped at 64 MiB (67108864 bytes).  A 64 MiB + 1 byte message must be rejected.
// NOTE: This test creates a 64 MiB + 1 byte file, which is large but within reason for a unit
// test.  If the test environment is constrained, remove this test or reduce the size.
TEST_F(IoTests, BoundedInput_OversizedMessageFile_DigestRejectsWithNonZero) {
    const std::string big_msg = tmp("io_bounded_msg.bin");
    write_zero_file(big_msg, 64U * 1024U * 1024U + 1U);

    const auto r = run_scli(scli(), {"digest", "--algo", "sha256", "--input", big_msg});
    EXPECT_NE(r.exit_code, 0);
}

// A base64 string encoding more than 64 KiB must be rejected for key inputs.
TEST_F(IoTests, BoundedInput_OversizedBase64Key_MacRejectsWithNonZero) {
    // 65537 bytes encodes to ceil(65537/3)*4 = 87384 base64 chars.
    // 87384 'A' chars decode to exactly 65538 bytes — one over the cap.
    const std::size_t encoded_len = ((65537U + 2U) / 3U) * 4U;
    std::string big_b64(encoded_len, 'A');

    const auto r = run_scli(scli(),
        {"mac", "--algo", "sha256",
         "--key", "base64:" + big_b64,
         "--input", "base64:" + std::string(kHelloB64)});
    EXPECT_NE(r.exit_code, 0);
}

// A base64 string encoding exactly 64 KiB must not be rejected by the bounded-
// input size guard (regression test for the pre-decode upper-bound off-by-one).
// The provider may still reject the key as too large, but the error must not be
// "exceeds maximum allowed size".
TEST_F(IoTests, BoundedInput_ExactCapBase64Key_NotRejectedBySizeGuard) {
    // 65536 = 21845*3 + 1 bytes → base64: 21845 "AAAA" groups + "AA==" = 87384 chars.
    std::string exact_cap_b64(21845U * 4U, 'A');
    exact_cap_b64 += "AA==";

    const auto r = run_scli(scli(),
        {"mac", "--algo", "sha256",
         "--key", "base64:" + exact_cap_b64,
         "--input", "base64:" + std::string(kHelloB64)});
    // Must not be rejected by the CLI size guard — any failure is from the provider.
    EXPECT_EQ(r.stderr_text.find("exceeds maximum"), std::string::npos);
}


// ─── pipe-drain stress tests ──────────────────────────────────────────────────
// These tests verify that run_scli drains stdout and stderr concurrently so
// neither pipe fills and deadlocks when the child writes more than one pipe
// buffer (~65 KiB on macOS/Linux) of output.

// Write 128 KiB of random bytes to stdout (raw binary via --output -).
// The output exceeds the typical pipe buffer; sequential draining would deadlock.
TEST_F(IoTests, PipeDrain_LargeStdoutDoesNotDeadlock) {
    constexpr std::size_t kLen = 128U * 1024U;  // 2× typical pipe buffer
    const auto r = run_scli(scli(), {"random", "--length", std::to_string(kLen), "--output", "-"});
    EXPECT_EQ(r.exit_code, 0);
    EXPECT_EQ(r.stdout_text.size(), kLen);
}

// Pass a key file larger than 64 KiB; the CLI writes a long error to stderr.
// The stdout is empty, confirming stderr-only output is captured correctly.
// The oversized data is written to a temp file rather than a command-line
// argument to avoid the Linux MAX_ARG_STRLEN (128 KiB) per-argument limit.
TEST_F(IoTests, PipeDrain_LargeStderrDoesNotDeadlock) {
    // Write 128 KiB of zero bytes — well above cli_key_max_bytes (64 KiB).
    const auto dir = tmp_dir("pipe_drain");
    std::filesystem::create_directory(dir);
    const auto key_path = dir / "big_key.bin";
    {
        std::ofstream f(key_path, std::ios::binary);
        constexpr std::size_t kKeySize = 128U * 1024U;
        const std::vector<char> zeros(kKeySize, '\0');
        f.write(zeros.data(), static_cast<std::streamsize>(kKeySize));
    }
    const auto r = run_scli(scli(),
        {"mac", "--algo", "sha256",
         "--key", key_path.string(),
         "--input", "base64:" + std::string(kHelloB64)});
    EXPECT_NE(r.exit_code, 0);
    EXPECT_NE(r.stderr_text.find("exceeds"), std::string::npos);
}


// ─── space-in-path regression ─────────────────────────────────────────────────

TEST_F(IoTests, SpaceInPath_DigestSucceeds) {
    // Create a temp directory with a space in its name.
    const auto dir = tmp_dir("io space dir");
    std::filesystem::create_directory(dir);

    // Write a small input file inside it (also with a space in the name).
    const auto in_path = dir / "input file.bin";
    {
        std::ofstream f(in_path, std::ios::binary);
        // Write raw "hello" bytes (0x68 0x65 0x6c 0x6c 0x6f).
        f << "hello";
    }

    const auto r = run_scli(scli(),
        {"digest", "--algo", "sha256", "--input", in_path.string()});
    EXPECT_EQ(r.exit_code, 0);
    // SHA-256("hello") in base64.
    EXPECT_EQ(r.stdout_text, "LPJNul+wow4m6DsqxbninhsWHlwfp0JecwQzYpOLmCQ=");
}

}  // namespace scli_test
