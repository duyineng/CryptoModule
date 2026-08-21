#include "config.hpp"
#include "key_manager.hpp"
#include "kms_client.hpp"
#include "pipe_server.hpp"

#include <curl/curl.h>
#include <google/protobuf/stubs/common.h>

#include <exception>
#include <iostream>
#include <string>

int main(int argc, char** argv) {
  const std::string config_path = argc > 1 ? argv[1] : "kmc.ini";
  if (curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK) {
    std::cerr << "[KMC] curl_global_init failed\n";
    return 1;
  }

  try {
    const KmcConfig config = load_config(config_path);
    KmsClient kms_client(config);
    KeyManager key_manager(config, kms_client);
    key_manager.initialize();
    const auto key = key_manager.current_key();
    std::cout << "[KMC] active key: " << key.key_id
              << ", expires_at_unix=" << key.expires_at_unix << '\n';
    key_manager.start_rotation();

    PipeServer pipe_server(config, key_manager);
    pipe_server.run();
    key_manager.stop();
  } catch (const std::exception& error) {
    std::cerr << "[KMC] fatal error: " << error.what() << '\n';
    curl_global_cleanup();
    google::protobuf::ShutdownProtobufLibrary();
    return 1;
  }

  curl_global_cleanup();
  google::protobuf::ShutdownProtobufLibrary();
  return 0;
}
