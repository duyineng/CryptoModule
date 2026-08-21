#pragma once

#include <cstdint>
#include <string>
#include <vector>

struct EncryptedData {
  std::vector<std::uint8_t> nonce;
  std::vector<std::uint8_t> ciphertext;
  std::vector<std::uint8_t> auth_tag;
};

EncryptedData aes_256_gcm_encrypt(
    const std::vector<std::uint8_t>& key,
    const std::string& plaintext);

std::string aes_256_gcm_decrypt(
    const std::vector<std::uint8_t>& key,
    const std::string& nonce,
    const std::string& ciphertext,
    const std::string& auth_tag);

void secure_clear(std::vector<std::uint8_t>& bytes);
