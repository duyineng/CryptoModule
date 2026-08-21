#include "pipe_protocol.hpp"

#include <array>

namespace {

bool read_exact(HANDLE pipe, void* buffer, DWORD size) {
  auto* output = static_cast<unsigned char*>(buffer);
  DWORD total = 0;
  while (total < size) {
    DWORD read = 0;
    if (!ReadFile(pipe, output + total, size - total, &read, nullptr) || read == 0) {
      return false;
    }
    total += read;
  }
  return true;
}

bool write_exact(HANDLE pipe, const void* buffer, DWORD size) {
  const auto* input = static_cast<const unsigned char*>(buffer);
  DWORD total = 0;
  while (total < size) {
    DWORD written = 0;
    if (!WriteFile(pipe, input + total, size - total, &written, nullptr) || written == 0) {
      return false;
    }
    total += written;
  }
  return true;
}

}  // namespace

bool read_frame(HANDLE pipe, std::string& payload) {
  std::array<unsigned char, 4> header{};
  if (!read_exact(pipe, header.data(), static_cast<DWORD>(header.size()))) {
    return false;
  }
  const std::uint32_t size =
      (static_cast<std::uint32_t>(header[0]) << 24U) |
      (static_cast<std::uint32_t>(header[1]) << 16U) |
      (static_cast<std::uint32_t>(header[2]) << 8U) |
      static_cast<std::uint32_t>(header[3]);
  constexpr std::uint32_t maximum_size = 16U * 1024U * 1024U;
  if (size == 0 || size > maximum_size) {
    return false;
  }
  payload.resize(size);
  return read_exact(pipe, payload.data(), size);
}

bool write_frame(HANDLE pipe, const std::string& payload) {
  const auto size = static_cast<std::uint32_t>(payload.size());
  const std::array<unsigned char, 4> header{
      static_cast<unsigned char>((size >> 24U) & 0xffU),
      static_cast<unsigned char>((size >> 16U) & 0xffU),
      static_cast<unsigned char>((size >> 8U) & 0xffU),
      static_cast<unsigned char>(size & 0xffU)};
  return write_exact(pipe, header.data(), static_cast<DWORD>(header.size())) &&
         write_exact(pipe, payload.data(), size);
}
