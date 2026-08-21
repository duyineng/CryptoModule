#include "key_manager.hpp"

#include "crypto.hpp"

#include <algorithm>
#include <chrono>
#include <iomanip>
#include <iostream>
#include <random>
#include <sstream>
#include <stdexcept>

namespace {

std::string new_request_id() {
  std::random_device random;
  std::uniform_int_distribution<unsigned int> byte(0, 255);
  unsigned char data[16];
  for (auto& value : data) {
    value = static_cast<unsigned char>(byte(random));
  }
  data[6] = static_cast<unsigned char>((data[6] & 0x0f) | 0x40);
  data[8] = static_cast<unsigned char>((data[8] & 0x3f) | 0x80);
  std::ostringstream stream;
  stream << std::hex << std::setfill('0');
  for (int index = 0; index < 16; ++index) {
    stream << std::setw(2) << static_cast<int>(data[index]);
    if (index == 3 || index == 5 || index == 7 || index == 9) {
      stream << '-';
    }
  }
  return stream.str();
}

}  // namespace

KeyManager::KeyManager(const KmcConfig& config, KmsClient& client)
    : config_(config), client_(client) {}

KeyManager::~KeyManager() {
  stop();
  std::lock_guard<std::mutex> lock(mutex_);
  for (auto& entry : keys_) {
    secure_clear(entry.second.material);
  }
}

void KeyManager::initialize() {
  install_key(client_.apply_work_key(new_request_id(), config_.algorithm, config_.key_length));
}

void KeyManager::start_rotation() {
  rotation_thread_ = std::thread(&KeyManager::rotation_loop, this);
}

void KeyManager::stop() {
  if (!stopping_.exchange(true)) {
    cv_.notify_all();
  }
  if (rotation_thread_.joinable()) {
    rotation_thread_.join();
  }
}

WorkKey KeyManager::current_key() const {
  std::lock_guard<std::mutex> lock(mutex_);
  const auto it = keys_.find(current_key_id_);
  if (it == keys_.end()) {
    throw std::runtime_error("no current work key");
  }
  return it->second;
}

WorkKey KeyManager::key_by_id(const std::string& key_id) const {
  std::lock_guard<std::mutex> lock(mutex_);
  const auto it = keys_.find(key_id);
  if (it == keys_.end()) {
    throw std::runtime_error("work key is not available in memory: " + key_id);
  }
  return it->second;
}

void KeyManager::install_key(const kmc::v1::WorkKeyResponse& response) {
  if (response.algorithm() != "AES" || response.key_length() != 256 ||
      response.key_material().size() != 32 || response.key_id().empty()) {
    throw std::runtime_error("KMS returned an unsupported work key");
  }
  WorkKey key;
  key.key_id = response.key_id();
  key.algorithm = response.algorithm();
  key.key_length = response.key_length();
  key.expires_at_unix = response.expires_at_unix();
  key.material.assign(response.key_material().begin(), response.key_material().end());

  std::lock_guard<std::mutex> lock(mutex_);
  keys_[key.key_id] = std::move(key);
  current_key_id_ = response.key_id();
  cv_.notify_all();
}

void KeyManager::rotation_loop() {
  while (!stopping_) {
    const WorkKey current = current_key();
    const auto rotate_at = std::chrono::system_clock::from_time_t(
        static_cast<std::time_t>(
            std::max<std::int64_t>(0, current.expires_at_unix - config_.rotation_lead_seconds)));

    std::unique_lock<std::mutex> lock(mutex_);
    if (cv_.wait_until(lock, rotate_at, [this, &current] {
          return stopping_ || current_key_id_ != current.key_id;
        })) {
      continue;
    }
    lock.unlock();

    try {
      const auto response = client_.rotate_work_key(
          new_request_id(), current.key_id, config_.algorithm, config_.key_length);
      install_key(response);
      std::cout << "[KMC] rotated key " << current.key_id << " -> "
                << response.key_id() << '\n';
    } catch (const std::exception& error) {
      std::cerr << "[KMC] key rotation failed: " << error.what()
                << "; retrying in 10 seconds\n";
      std::unique_lock<std::mutex> retry_lock(mutex_);
      cv_.wait_for(retry_lock, std::chrono::seconds(10), [this] { return stopping_.load(); });
    }
  }
}
