#pragma once

#include "config.hpp"
#include "kms_client.hpp"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <map>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

struct WorkKey {
  std::string key_id;
  std::string algorithm;
  std::uint32_t key_length = 0;
  std::int64_t expires_at_unix = 0;
  std::vector<std::uint8_t> material;
};

class KeyManager {
 public:
  KeyManager(const KmcConfig& config, KmsClient& client);
  ~KeyManager();

  void initialize();
  void start_rotation();
  void stop();

  WorkKey current_key() const;
  WorkKey key_by_id(const std::string& key_id) const;

 private:
  void install_key(const kmc::v1::WorkKeyResponse& response);
  void rotation_loop();

  KmcConfig config_;
  KmsClient& client_;
  mutable std::mutex mutex_;
  std::condition_variable cv_;
  std::map<std::string, WorkKey> keys_;
  std::string current_key_id_;
  std::atomic<bool> stopping_{false};
  std::thread rotation_thread_;
};
