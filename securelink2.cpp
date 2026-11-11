// Zohaib Umer | 23i-0528 | CS3002 Assignment 2, Part C
// SmartLock v2: suite policy, HKDF, per-record nonces, sequence-bound AES-GCM.
#include "securelink2.hpp"
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <algorithm>
#include <array>
#include <climits>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

namespace sl2 {
namespace {
using Bytes = std::vector<uint8_t>;

std::array<uint8_t, 8> encode_seq(uint64_t n) {
    std::array<uint8_t, 8> result{};
    for (int i = 7; i >= 0; --i) {
        result[static_cast<size_t>(i)] = static_cast<uint8_t>(n & 0xffu);
        n >>= 8;
    }
    return result;
}

uint64_t decode_seq(const Bytes& input) {
    uint64_t value = 0;
    for (size_t i = 0; i < 8; ++i)
        value = (value << 8) | input[i];
    return value;
}

const EVP_CIPHER* selected_cipher(size_t key_length) {
    if (key_length == 32) return EVP_aes_256_gcm();
    if (key_length == 16) return EVP_aes_128_gcm();
    throw std::invalid_argument("Invalid AES-GCM key length");
}

void check_size(size_t size) {
    if (size > static_cast<size_t>(INT_MAX))
        throw std::length_error("Record too long for OpenSSL");
}

struct CipherDeleter {
    void operator()(EVP_CIPHER_CTX* ctx) const { EVP_CIPHER_CTX_free(ctx); }
};
using CipherCtx = std::unique_ptr<EVP_CIPHER_CTX, CipherDeleter>;

struct KdfDeleter { void operator()(EVP_KDF* kdf) const { EVP_KDF_free(kdf); } };
struct KdfCtxDeleter { void operator()(EVP_KDF_CTX* ctx) const { EVP_KDF_CTX_free(ctx); } };

} // namespace

std::vector<std::string> strong_suites() {
    return {"AES256-GCM", "AES128-GCM"};
}

std::string choose_suite(const std::vector<std::string>& hub_offer) {
    for (const auto& accepted : strong_suites()) {
        if (std::find(hub_offer.begin(), hub_offer.end(), accepted) != hub_offer.end())
            return accepted;
    }
    return "";
}

std::vector<uint8_t> derive_key(const std::vector<uint8_t>& shared_secret,
                                const std::string& suite, const std::string& context) {
    int out_len = keylen(suite);
    if (!out_len) throw std::invalid_argument("Unsupported cipher suite");
    if (shared_secret.empty()) throw std::invalid_argument("Empty DH secret");
    if (context.empty()) throw std::invalid_argument("Missing key-derivation context");

    std::unique_ptr<EVP_KDF, KdfDeleter> kdf(EVP_KDF_fetch(nullptr, "HKDF", nullptr));
    if (!kdf) throw std::runtime_error("HKDF unavailable");
    std::unique_ptr<EVP_KDF_CTX, KdfCtxDeleter> ctx(EVP_KDF_CTX_new(kdf.get()));
    if (!ctx) throw std::runtime_error("Cannot initialize HKDF context");

    std::string info = "SmartLock-v2|" + suite + "|" + context;
    const std::string salt = "SmartLock-v2-HKDF-SHA256";
    const char* digest = "SHA256";
    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, const_cast<char*>(digest), 0),
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY,
            const_cast<uint8_t*>(shared_secret.data()), shared_secret.size()),
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT,
            const_cast<char*>(salt.data()), salt.size()),
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO,
            const_cast<char*>(info.data()), info.size()),
        OSSL_PARAM_construct_end()
    };
    Bytes result(static_cast<size_t>(out_len));
    if (EVP_KDF_derive(ctx.get(), result.data(), result.size(), params) <= 0)
        throw std::runtime_error("HKDF key derivation failed");
    return result;
}

std::vector<uint8_t> make_nonce(uint64_t seqno) {
    Bytes nonce(12, 0);
    auto seq = encode_seq(seqno);
    std::copy(seq.begin(), seq.end(), nonce.begin() + 4);
    return nonce;
}

std::vector<uint8_t> seal(const std::vector<uint8_t>& key, uint64_t seqno,
                          const std::string& plaintext) {
    const EVP_CIPHER* cipher = selected_cipher(key.size());
    check_size(plaintext.size());
    auto seq = encode_seq(seqno);
    Bytes nonce = make_nonce(seqno);
    CipherCtx ctx(EVP_CIPHER_CTX_new());
    if (!ctx) throw std::runtime_error("Cannot create cipher context");
    if (EVP_EncryptInit_ex(ctx.get(), cipher, nullptr, nullptr, nullptr) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, 12, nullptr) != 1 ||
        EVP_EncryptInit_ex(ctx.get(), nullptr, nullptr, key.data(), nonce.data()) != 1)
        throw std::runtime_error("AES-GCM encryption initialization failed");

    int len = 0;
    if (EVP_EncryptUpdate(ctx.get(), nullptr, &len, seq.data(), 8) != 1)
        throw std::runtime_error("AES-GCM AAD failed");

    Bytes result(8 + plaintext.size() + 16);
    std::copy(seq.begin(), seq.end(), result.begin());
    int written = 0;
    if (EVP_EncryptUpdate(ctx.get(), result.data() + 8, &written,
                          reinterpret_cast<const unsigned char*>(plaintext.data()),
                          static_cast<int>(plaintext.size())) != 1)
        throw std::runtime_error("AES-GCM encryption failed");
    int final_len = 0;
    if (EVP_EncryptFinal_ex(ctx.get(), result.data() + 8 + written, &final_len) != 1)
        throw std::runtime_error("AES-GCM finalization failed");
    size_t cipher_len = static_cast<size_t>(written + final_len);
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG, 16,
                            result.data() + 8 + cipher_len) != 1)
        throw std::runtime_error("AES-GCM tag generation failed");
    result.resize(8 + cipher_len + 16);
    return result; // 8-byte big-endian sequence | ciphertext | 16-byte tag
}

std::string open_record(const std::vector<uint8_t>& key,
                        const std::vector<uint8_t>& record,
                        uint64_t expected_seqno) {
    const EVP_CIPHER* cipher = selected_cipher(key.size());
    if (record.size() < 8 + 16)
        throw std::invalid_argument("Truncated AEAD record");
    auto received_seq = decode_seq(record);
    if (received_seq != expected_seqno)
        throw std::runtime_error("Replay or out-of-order record");
    size_t cipher_len = record.size() - 8 - 16;
    check_size(cipher_len);
    Bytes nonce = make_nonce(received_seq);
    CipherCtx ctx(EVP_CIPHER_CTX_new());
    if (!ctx) throw std::runtime_error("Cannot create cipher context");
    if (EVP_DecryptInit_ex(ctx.get(), cipher, nullptr, nullptr, nullptr) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, 12, nullptr) != 1 ||
        EVP_DecryptInit_ex(ctx.get(), nullptr, nullptr, key.data(), nonce.data()) != 1)
        throw std::runtime_error("AES-GCM decryption initialization failed");

    int len = 0;
    if (EVP_DecryptUpdate(ctx.get(), nullptr, &len, record.data(), 8) != 1)
        throw std::runtime_error("AES-GCM AAD failed");
    Bytes plaintext(cipher_len + 16);
    int written = 0;
    if (EVP_DecryptUpdate(ctx.get(), plaintext.data(), &written,
                          record.data() + 8, static_cast<int>(cipher_len)) != 1)
        throw std::runtime_error("AES-GCM decryption failed");
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG, 16,
                             const_cast<uint8_t*>(record.data() + 8 + cipher_len)) != 1)
        throw std::runtime_error("AES-GCM tag setup failed");
    int tail = 0;
    if (EVP_DecryptFinal_ex(ctx.get(), plaintext.data() + written, &tail) != 1)
        throw std::runtime_error("AEAD authentication failed");
    plaintext.resize(static_cast<size_t>(written + tail));
    return std::string(plaintext.begin(), plaintext.end());
}
} // namespace sl2
