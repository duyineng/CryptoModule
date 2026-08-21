#include "crypto.hpp"

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include <memory>
#include <stdexcept>

namespace {

using CipherContext = std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)>;

void require_key(const std::vector<std::uint8_t>& key) {
  if (key.size() != 32) {
    throw std::runtime_error("AES-256-GCM requires a 32-byte key");
  }
}

}  // namespace

EncryptedData aes_256_gcm_encrypt(
    const std::vector<std::uint8_t>& key,
    const std::string& plaintext) {
  require_key(key);

  EncryptedData result;
  result.nonce.resize(12);
  result.auth_tag.resize(16);
  result.ciphertext.resize(plaintext.size() + 16);
  if (RAND_bytes(result.nonce.data(), static_cast<int>(result.nonce.size())) != 1) {
    throw std::runtime_error("RAND_bytes failed");
  }

  CipherContext context(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
  if (!context) {
    throw std::runtime_error("EVP_CIPHER_CTX_new failed");
  }

  int written = 0;
  int total = 0;
  if (EVP_EncryptInit_ex(context.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1 ||
      EVP_CIPHER_CTX_ctrl(
          context.get(), EVP_CTRL_GCM_SET_IVLEN,
          static_cast<int>(result.nonce.size()), nullptr) != 1 ||
      EVP_EncryptInit_ex(
          context.get(), nullptr, nullptr, key.data(), result.nonce.data()) != 1 ||
      EVP_EncryptUpdate(
          context.get(), result.ciphertext.data(), &written,
          reinterpret_cast<const unsigned char*>(plaintext.data()),
          static_cast<int>(plaintext.size())) != 1) {
    throw std::runtime_error("AES-GCM encryption initialization failed");
  }
  total = written;
  if (EVP_EncryptFinal_ex(context.get(), result.ciphertext.data() + total, &written) != 1) {
    throw std::runtime_error("AES-GCM encryption failed");
  }
  total += written;
  result.ciphertext.resize(static_cast<std::size_t>(total));
  if (EVP_CIPHER_CTX_ctrl(
          context.get(), EVP_CTRL_GCM_GET_TAG,
          static_cast<int>(result.auth_tag.size()), result.auth_tag.data()) != 1) {
    throw std::runtime_error("AES-GCM tag extraction failed");
  }
  return result;
}

std::string aes_256_gcm_decrypt(
    const std::vector<std::uint8_t>& key,
    const std::string& nonce,
    const std::string& ciphertext,
    const std::string& auth_tag) {
  require_key(key);
  if (nonce.size() != 12 || auth_tag.size() != 16) {
    throw std::runtime_error("invalid AES-GCM nonce or tag length");
  }

  CipherContext context(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
  if (!context) {
    throw std::runtime_error("EVP_CIPHER_CTX_new failed");
  }

  std::string plaintext(ciphertext.size(), '\0');
  int written = 0;
  int total = 0;
  if (EVP_DecryptInit_ex(context.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1 ||
      EVP_CIPHER_CTX_ctrl(
          context.get(), EVP_CTRL_GCM_SET_IVLEN,
          static_cast<int>(nonce.size()), nullptr) != 1 ||
      EVP_DecryptInit_ex(
          context.get(), nullptr, nullptr, key.data(),
          reinterpret_cast<const unsigned char*>(nonce.data())) != 1 ||
      EVP_DecryptUpdate(
          context.get(), reinterpret_cast<unsigned char*>(plaintext.data()), &written,
          reinterpret_cast<const unsigned char*>(ciphertext.data()),
          static_cast<int>(ciphertext.size())) != 1) {
    throw std::runtime_error("AES-GCM decryption initialization failed");
  }
  total = written;
  if (EVP_CIPHER_CTX_ctrl(
          context.get(), EVP_CTRL_GCM_SET_TAG,
          static_cast<int>(auth_tag.size()),
          const_cast<char*>(auth_tag.data())) != 1) {
    throw std::runtime_error("AES-GCM tag setup failed");
  }
  if (EVP_DecryptFinal_ex(
          context.get(), reinterpret_cast<unsigned char*>(plaintext.data()) + total,
          &written) != 1) {
    throw std::runtime_error("AES-GCM authentication failed");
  }
  total += written;
  plaintext.resize(static_cast<std::size_t>(total));
  return plaintext;
}

void secure_clear(std::vector<std::uint8_t>& bytes) {
  if (!bytes.empty()) {
    OPENSSL_cleanse(bytes.data(), bytes.size());
    bytes.clear();
    bytes.shrink_to_fit();
  }
}
