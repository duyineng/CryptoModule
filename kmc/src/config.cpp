#include "config.hpp"

#include <algorithm>
#include <cctype>
#include <fstream>
#include <map>
#include <filesystem>
#include <stdexcept>

namespace {

std::string trim(std::string value) {
  const auto first = std::find_if_not(value.begin(), value.end(), [](unsigned char ch) {
    return std::isspace(ch) != 0;
  });
  const auto last = std::find_if_not(value.rbegin(), value.rend(), [](unsigned char ch) {
    return std::isspace(ch) != 0;
  }).base();
  return first < last ? std::string(first, last) : std::string{};
}

std::string required(const std::map<std::string, std::string>& values, const std::string& key) {
  const auto it = values.find(key);
  if (it == values.end() || it->second.empty()) {
    throw std::runtime_error("missing configuration value: " + key);
  }
  return it->second;
}

}  // namespace

KmcConfig load_config(const std::string& path) {
  std::ifstream input(path);
  if (!input) {
    throw std::runtime_error("cannot open configuration file: " + path);
  }

  std::map<std::string, std::string> values;
  std::string section;
  std::string line;
  while (std::getline(input, line)) {
    line = trim(line);
    if (line.empty() || line.front() == ';' || line.front() == '#') {
      continue;
    }
    if (line.front() == '[' && line.back() == ']') {
      section = trim(line.substr(1, line.size() - 2));
      continue;
    }
    const auto separator = line.find('=');
    if (separator == std::string::npos) {
      continue;
    }
    const auto key = trim(line.substr(0, separator));
    const auto value = trim(line.substr(separator + 1));
    values[section + "." + key] = value;
  }

  KmcConfig config;
  config.base_url = required(values, "kms.base_url");
  config.connect_timeout_seconds = std::stol(required(values, "kms.connect_timeout_seconds"));
  config.request_timeout_seconds = std::stol(required(values, "kms.request_timeout_seconds"));
  const auto config_directory = std::filesystem::absolute(std::filesystem::path(path)).parent_path();
  auto resolve_path = [&config_directory](const std::string& value) {
    const std::filesystem::path configured(value);
    return (configured.is_absolute() ? configured : config_directory / configured).lexically_normal().string();
  };
  config.ca_cert = resolve_path(required(values, "tls.ca_cert"));
  config.client_cert = resolve_path(required(values, "tls.client_cert"));
  config.client_key = resolve_path(required(values, "tls.client_key"));
  config.algorithm = required(values, "key.algorithm");
  config.key_length = static_cast<std::uint32_t>(std::stoul(required(values, "key.key_length")));
  config.rotation_lead_seconds = std::stoll(required(values, "key.rotation_lead_seconds"));
  config.pipe_name = required(values, "pipe.name");
  return config;
}
