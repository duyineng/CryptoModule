#pragma once

#include <cstdint>
#include <string>

struct KmcConfig {
  std::string base_url;
  long connect_timeout_seconds = 10;
  long request_timeout_seconds = 30;
  std::string ca_cert;
  std::string client_cert;
  std::string client_key;
  std::string algorithm = "AES";
  std::uint32_t key_length = 256;
  std::int64_t rotation_lead_seconds = 60;
  std::string pipe_name = R"(\\.\pipe\KMC_Crypto)";
};

KmcConfig load_config(const std::string& path);
