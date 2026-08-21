#pragma once

#include "config.hpp"
#include "key_manager.hpp"

#include <atomic>

class PipeServer {
 public:
  PipeServer(const KmcConfig& config, KeyManager& key_manager);
  void run();
  void stop();

 private:
  void handle_client(void* pipe_handle);

  KmcConfig config_;
  KeyManager& key_manager_;
  std::atomic<bool> stopping_{false};
};
