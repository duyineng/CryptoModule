#include "kmc.pb.h"

#include <windows.h>

#include <array>
#include <cstdint>
#include <iostream>
#include <stdexcept>
#include <string>

namespace {

bool write_exact(HANDLE pipe, const void* buffer, DWORD size) {
  const auto* input = static_cast<const unsigned char*>(buffer);
  DWORD total = 0;
  while (total < size) {
    DWORD written = 0;
    if (!WriteFile(pipe, input + total, size - total, &written, nullptr)) return false;
    total += written;
  }
  return true;
}

bool read_exact(HANDLE pipe, void* buffer, DWORD size) {
  auto* output = static_cast<unsigned char*>(buffer);
  DWORD total = 0;
  while (total < size) {
    DWORD read = 0;
    if (!ReadFile(pipe, output + total, size - total, &read, nullptr)) return false;
    total += read;
  }
  return true;
}

void write_message(HANDLE pipe, const google::protobuf::MessageLite& message) {
  const std::string payload = message.SerializeAsString();
  const auto size = static_cast<std::uint32_t>(payload.size());
  const std::array<unsigned char, 4> header{
      static_cast<unsigned char>(size >> 24U),
      static_cast<unsigned char>(size >> 16U),
      static_cast<unsigned char>(size >> 8U),
      static_cast<unsigned char>(size)};
  if (!write_exact(pipe, header.data(), 4) ||
      !write_exact(pipe, payload.data(), static_cast<DWORD>(payload.size()))) {
    throw std::runtime_error("pipe write failed");
  }
}

kmc::v1::SdkResponse read_response(HANDLE pipe) {
  std::array<unsigned char, 4> header{};
  if (!read_exact(pipe, header.data(), 4)) throw std::runtime_error("pipe read failed");
  const std::uint32_t size =
      (static_cast<std::uint32_t>(header[0]) << 24U) |
      (static_cast<std::uint32_t>(header[1]) << 16U) |
      (static_cast<std::uint32_t>(header[2]) << 8U) | header[3];
  std::string payload(size, '\0');
  if (!read_exact(pipe, payload.data(), size)) throw std::runtime_error("pipe read failed");
  kmc::v1::SdkResponse response;
  if (!response.ParseFromString(payload)) throw std::runtime_error("invalid response");
  return response;
}

}  // namespace

int main(int argc, char** argv) {
  const std::string plaintext = argc > 1 ? argv[1] : "hello from sdk_demo";
  const char* pipe_name = R"(\\.\pipe\KMC_Crypto)";
  if (!WaitNamedPipeA(pipe_name, 5000)) {
    std::cerr << "KMC pipe is not available\n";
    return 1;
  }
  HANDLE pipe = CreateFileA(
      pipe_name, GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
  if (pipe == INVALID_HANDLE_VALUE) {
    std::cerr << "CreateFile(pipe) failed: " << GetLastError() << '\n';
    return 1;
  }

  try {
    kmc::v1::SdkRequest encrypt;
    encrypt.set_request_id("sdk-demo-encrypt");
    encrypt.mutable_encrypt()->set_plaintext(plaintext);
    write_message(pipe, encrypt);
    const auto encrypted = read_response(pipe);
    if (encrypted.status() != "OK") throw std::runtime_error(encrypted.error());
    std::cout << "encrypted with key_id=" << encrypted.key_id()
              << ", ciphertext_bytes=" << encrypted.ciphertext().size() << '\n';

    kmc::v1::SdkRequest decrypt;
    decrypt.set_request_id("sdk-demo-decrypt");
    auto* operation = decrypt.mutable_decrypt();
    operation->set_key_id(encrypted.key_id());
    operation->set_nonce(encrypted.nonce());
    operation->set_ciphertext(encrypted.ciphertext());
    operation->set_auth_tag(encrypted.auth_tag());
    write_message(pipe, decrypt);
    const auto decrypted = read_response(pipe);
    if (decrypted.status() != "OK") throw std::runtime_error(decrypted.error());
    std::cout << "decrypted plaintext: " << decrypted.plaintext() << '\n';
  } catch (const std::exception& error) {
    std::cerr << "sdk_demo failed: " << error.what() << '\n';
    CloseHandle(pipe);
    return 1;
  }
  CloseHandle(pipe);
  return 0;
}
