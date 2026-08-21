#pragma once

#include "config.hpp"
#include "kmc.pb.h"

#include <string>

class KmsClient {
 public:
  explicit KmsClient(const KmcConfig& config);

  kmc::v1::WorkKeyResponse apply_work_key(
      const std::string& request_id,
      const std::string& algorithm,
      std::uint32_t key_length);

  kmc::v1::WorkKeyResponse rotate_work_key(
      const std::string& request_id,
      const std::string& current_key_id,
      const std::string& algorithm,
      std::uint32_t key_length);

 private:
  kmc::v1::WorkKeyResponse post_protobuf(
      const std::string& url,
      const std::string& request_id,
      const std::string& request_body);

  KmcConfig config_;
};
