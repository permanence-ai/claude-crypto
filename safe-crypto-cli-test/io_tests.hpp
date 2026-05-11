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

    std::vector<std::string> tmp_files_;
};


// ─── digest ──────────────────────────────────────────────────────────────────

TEST_F(IoTests, Digest_Base64Input_FileOutput) {
    const std::string out_path = tmp("io_digest_out.bin");
    const auto r = run_scli(scli(),
        "digest --algo sha256 --input base64:" + std::string(kHelloB64) +
        " --output " + out_path);
    EXPECT_EQ(r.exit_code, 0);
    // Output file should contain 32 raw bytes.
    EXPECT_EQ(std::filesystem::file_size(out_path), 32U);
}

TEST_F(IoTests, Digest_FileInput_StdoutOutput) {
    const std::string in_path = tmp_b64("io_digest_in.bin", kHelloB64);
    const auto r = run_scli(scli(),
        "digest --algo sha256 --input " + in_path);
    EXPECT_EQ(r.exit_code, 0);
    // SHA-256("hello") in base64.
    EXPECT_EQ(r.stdout_text, "LPJNul+wow4m6DsqxbninhsWHlwfp0JecwQzYpOLmCQ=");
}

TEST_F(IoTests, Digest_FileInput_FileOutput) {
    const std::string in_path  = tmp_b64("io_digest_in2.bin", kHelloB64);
    const std::string out_path = tmp("io_digest_out2.bin");
    const auto r = run_scli(scli(),
        "digest --algo sha256 --input " + in_path + " --output " + out_path);
    EXPECT_EQ(r.exit_code, 0);
    EXPECT_EQ(std::filesystem::file_size(out_path), 32U);
}


// ─── mac ─────────────────────────────────────────────────────────────────────

TEST_F(IoTests, Mac_Base64Input_FileOutput) {
    const std::string out_path = tmp("io_mac_out.bin");
    const auto r = run_scli(scli(),
        "mac --algo sha256"
        " --key base64:" + std::string(kKeyB64) +
        " --input base64:" + std::string(kHelloB64) +
        " --output " + out_path);
    EXPECT_EQ(r.exit_code, 0);
    // HMAC-SHA-256 output is 32 bytes.
    EXPECT_EQ(std::filesystem::file_size(out_path), 32U);
}

TEST_F(IoTests, Mac_FileKey_Base64Input_StdoutOutput) {
    // Key from file, message from base64.
    const std::string key_path = tmp_b64("io_mac_key.bin", kKeyB64);
    const auto r = run_scli(scli(),
        "mac --algo sha256"
        " --key " + key_path +
        " --input base64:" + std::string(kHelloB64));
    EXPECT_EQ(r.exit_code, 0);
    EXPECT_FALSE(r.stdout_text.empty());
}

TEST_F(IoTests, Mac_Base64Key_FileInput_StdoutOutput) {
    // Key from base64, message from file.
    const std::string msg_path = tmp_b64("io_mac_msg.bin", kHelloB64);
    const auto r = run_scli(scli(),
        "mac --algo sha256"
        " --key base64:" + std::string(kKeyB64) +
        " --input " + msg_path);
    EXPECT_EQ(r.exit_code, 0);
    EXPECT_FALSE(r.stdout_text.empty());
}

TEST_F(IoTests, Mac_FileKey_FileInput_FileOutput) {
    const std::string key_path = tmp_b64("io_mac_key2.bin", kKeyB64);
    const std::string msg_path = tmp_b64("io_mac_msg2.bin", kHelloB64);
    const std::string out_path = tmp("io_mac_out2.bin");
    const auto r = run_scli(scli(),
        "mac --algo sha256"
        " --key " + key_path +
        " --input " + msg_path +
        " --output " + out_path);
    EXPECT_EQ(r.exit_code, 0);
    EXPECT_EQ(std::filesystem::file_size(out_path), 32U);
}

TEST_F(IoTests, Mac_MixedInputs_VerifyFromFile) {
    // Generate MAC with base64 inputs, write to file, then verify reading
    // both message and MAC from files.
    const std::string mac_path = tmp("io_mac_verify.bin");
    const auto gen = run_scli(scli(),
        "mac --algo sha256"
        " --key base64:" + std::string(kKeyB64) +
        " --input base64:" + std::string(kHelloB64) +
        " --output " + mac_path);
    ASSERT_EQ(gen.exit_code, 0);

    const std::string msg_path = tmp_b64("io_mac_msg3.bin", kHelloB64);

    // Verify: key from base64 cmd line, message from file, MAC from file.
    const auto verify = run_scli(scli(),
        "mac --algo sha256"
        " --key base64:" + std::string(kKeyB64) +
        " --input " + msg_path +
        " --verify " + mac_path);
    EXPECT_EQ(verify.exit_code, 0);
}


// ─── aead ─────────────────────────────────────────────────────────────────────

TEST_F(IoTests, Aead_Base64Input_FileOutput_RoundTrip) {
    const std::string ct_path  = tmp("io_aead_ct.bin");
    const std::string key_spec = "base64:" + std::string(kKeyB64);

    // Encrypt: base64 plaintext → ciphertext file.
    const auto enc = run_scli(scli(),
        "aead --algo aes256-gcm --op encrypt"
        " --key " + key_spec +
        " --input base64:" + std::string(kHelloWorldB64) +
        " --output " + ct_path);
    ASSERT_EQ(enc.exit_code, 0);

    // Decrypt: ciphertext file → base64 stdout.
    const auto dec = run_scli(scli(),
        "aead --algo aes256-gcm --op decrypt"
        " --key " + key_spec +
        " --input " + ct_path);
    EXPECT_EQ(dec.exit_code, 0);
    EXPECT_EQ(dec.stdout_text, kHelloWorldB64);
}

TEST_F(IoTests, Aead_FileInput_StdoutOutput_RoundTrip) {
    const std::string pt_path = tmp_b64("io_aead_pt.bin", kHelloWorldB64);
    const std::string key_spec = "base64:" + std::string(kKeyB64);

    // Encrypt: plaintext file → base64 stdout.
    const auto enc = run_scli(scli(),
        "aead --algo aes256-gcm --op encrypt"
        " --key " + key_spec +
        " --input " + pt_path);
    ASSERT_EQ(enc.exit_code, 0);

    // Decrypt: base64 ciphertext from stdout → base64 stdout.
    const auto dec = run_scli(scli(),
        "aead --algo aes256-gcm --op decrypt"
        " --key " + key_spec +
        " --input base64:" + enc.stdout_text);
    EXPECT_EQ(dec.exit_code, 0);
    EXPECT_EQ(dec.stdout_text, kHelloWorldB64);
}

TEST_F(IoTests, Aead_FileInput_FileOutput_RoundTrip) {
    const std::string pt_path  = tmp_b64("io_aead_pt2.bin", kHelloWorldB64);
    const std::string ct_path  = tmp("io_aead_ct2.bin");
    const std::string pt2_path = tmp("io_aead_pt2_dec.bin");
    const std::string key_spec = "base64:" + std::string(kKeyB64);

    const auto enc = run_scli(scli(),
        "aead --algo aes256-gcm --op encrypt"
        " --key " + key_spec +
        " --input " + pt_path +
        " --output " + ct_path);
    ASSERT_EQ(enc.exit_code, 0);

    const auto dec = run_scli(scli(),
        "aead --algo aes256-gcm --op decrypt"
        " --key " + key_spec +
        " --input " + ct_path +
        " --output " + pt2_path);
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
        "aead --algo aes256-gcm --op encrypt"
        " --key " + key_path +
        " --input base64:" + std::string(kHelloWorldB64) +
        " --output " + ct_path);
    ASSERT_EQ(enc.exit_code, 0);

    const auto dec = run_scli(scli(),
        "aead --algo aes256-gcm --op decrypt"
        " --key base64:" + std::string(kKeyB64) +
        " --input " + ct_path);
    EXPECT_EQ(dec.exit_code, 0);
    EXPECT_EQ(dec.stdout_text, kHelloWorldB64);
}

TEST_F(IoTests, Aead_MixedIO_AadFromFile) {
    // Encrypt with AAD from a file, then decrypt with AAD from base64.
    const std::string aad_path = tmp_b64("io_aead_aad.bin", "bXkgYWFk");  // "my aad"
    const std::string key_spec = "base64:" + std::string(kKeyB64);

    const auto enc = run_scli(scli(),
        "aead --algo aes256-gcm --op encrypt"
        " --key " + key_spec +
        " --input base64:" + std::string(kHelloWorldB64) +
        " --aad " + aad_path);
    ASSERT_EQ(enc.exit_code, 0);

    const auto dec = run_scli(scli(),
        "aead --algo aes256-gcm --op decrypt"
        " --key " + key_spec +
        " --input base64:" + enc.stdout_text +
        " --aad base64:bXkgYWFk");
    EXPECT_EQ(dec.exit_code, 0);
    EXPECT_EQ(dec.stdout_text, kHelloWorldB64);
}


// ─── random ───────────────────────────────────────────────────────────────────

TEST_F(IoTests, Random_FileOutput) {
    const std::string out_path = tmp("io_random_out.bin");
    const auto r = run_scli(scli(), "random --length 32 --output " + out_path);
    EXPECT_EQ(r.exit_code, 0);
    EXPECT_EQ(std::filesystem::file_size(out_path), 32U);
}

TEST_F(IoTests, Random_FileOutput_ContentIsRandom) {
    const std::string p1 = tmp("io_random_a.bin");
    const std::string p2 = tmp("io_random_b.bin");
    const auto r1 = run_scli(scli(), "random --length 32 --output " + p1);
    const auto r2 = run_scli(scli(), "random --length 32 --output " + p2);
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
        "ecdsa keygen --curve p256"
        " --out-private " + priv_path +
        " --out-public "  + pub_path);
    ASSERT_EQ(r.exit_code, 0);

    struct stat st{};
    ASSERT_EQ(::stat(priv_path.c_str(), &st), 0);
    EXPECT_EQ(st.st_mode & 0777U, 0600U);  // NOLINT(cppcoreguidelines-avoid-magic-numbers)
}

TEST_F(IoTests, SecretOutput_PublicKeyFile_HasDefaultUmaskMode) {
    const std::string priv_path = tmp("io_perm_priv2.der");
    const std::string pub_path  = tmp("io_perm_pub2.der");

    const auto r = run_scli(scli(),
        "ecdsa keygen --curve p256"
        " --out-private " + priv_path +
        " --out-public "  + pub_path);
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
        "ecdsa keygen --curve p256"
        " --out-private " + priv_path +
        " --out-public "  + pub_path);
    ASSERT_EQ(r1.exit_code, 0);

    // Second keygen must fail: private key file already exists.
    // Remove pub so it does not interfere.
    std::filesystem::remove(pub_path);
    const std::string pub_path2 = tmp("io_perm_exist_pub2.der");
    const auto r2 = run_scli(scli(),
        "ecdsa keygen --curve p256"
        " --out-private " + priv_path +
        " --out-public "  + pub_path2);
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
        "ecdsa keygen --curve p256"
        " --out-private " + link_path +
        " --out-public "  + pub_path);
    EXPECT_NE(r.exit_code, 0);

    std::filesystem::remove(real_path);
}


// ─── ecdsa ────────────────────────────────────────────────────────────────────

TEST_F(IoTests, Ecdsa_Base64Key_FileInput_FileOutput_RoundTrip) {
    // keygen to files, sign with message from file, write sig to file, verify.
    const std::string priv_path = tmp("io_ecdsa_priv.der");
    const std::string pub_path  = tmp("io_ecdsa_pub.der");
    const std::string msg_path  = tmp_b64("io_ecdsa_msg.bin", kHelloWorldB64);
    const std::string sig_path  = tmp("io_ecdsa_sig.bin");

    const auto kg = run_scli(scli(),
        "ecdsa keygen --curve p256"
        " --out-private " + priv_path +
        " --out-public "  + pub_path);
    ASSERT_EQ(kg.exit_code, 0);

    // Sign: key from file, message from file, signature to file.
    const auto sig = run_scli(scli(),
        "ecdsa sign --curve p256"
        " --key "    + priv_path +
        " --input "  + msg_path +
        " --output " + sig_path);
    ASSERT_EQ(sig.exit_code, 0);

    // Verify: key from file, message from base64 cmd line, signature from file.
    const auto verify = run_scli(scli(),
        "ecdsa verify --curve p256"
        " --key "       + pub_path +
        " --input base64:" + std::string(kHelloWorldB64) +
        " --signature " + sig_path);
    EXPECT_EQ(verify.exit_code, 0);
}

}  // namespace scli_test
