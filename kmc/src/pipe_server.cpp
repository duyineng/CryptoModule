#include "pipe_server.hpp"

#include "crypto.hpp"
#include "kmc.pb.h"
#include "pipe_protocol.hpp"

#include <windows.h>

#include <iostream>
#include <stdexcept>
#include <string>

PipeServer::PipeServer(const KmcConfig& config, KeyManager& key_manager)
    : config_(config), key_manager_(key_manager) {}

void PipeServer::run() {
  std::cout << "[KMC] named pipe ready: " << config_.pipe_name << '\n';
  while (!stopping_) {
    HANDLE pipe = CreateNamedPipeA(
        config_.pipe_name.c_str(), PIPE_ACCESS_DUPLEX,
        PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
        1, 64 * 1024, 64 * 1024, 0, nullptr);
    if (pipe == INVALID_HANDLE_VALUE) {
      throw std::runtime_error("CreateNamedPipe failed: " + std::to_string(GetLastError()));
    }

    const BOOL connected = ConnectNamedPipe(pipe, nullptr)
                               ? TRUE
                               : (GetLastError() == ERROR_PIPE_CONNECTED);
    if (connected) {
      handle_client(pipe);
    }
    FlushFileBuffers(pipe);
    DisconnectNamedPipe(pipe);
    CloseHandle(pipe);
  }
}

void PipeServer::stop() {
  stopping_ = true;
}

void PipeServer::handle_client(void* pipe_handle) {
  HANDLE pipe = static_cast<HANDLE>(pipe_handle);
  std::string payload;
  while (read_frame(pipe, payload)) {
    kmc::v1::SdkRequest request;
    kmc::v1::SdkResponse response;
    if (!request.ParseFromString(payload)) {
      response.set_status("ERROR");
      response.set_error("invalid protobuf request");
    } else {
      response.set_request_id(request.request_id());
      try {
        if (request.has_encrypt()) {
          const WorkKey key = key_manager_.current_key();
          const auto encrypted = aes_256_gcm_encrypt(key.material, request.encrypt().plaintext());
          response.set_status("OK");
          response.set_key_id(key.key_id);
          response.set_nonce(encrypted.nonce.data(), encrypted.nonce.size());
          response.set_ciphertext(encrypted.ciphertext.data(), encrypted.ciphertext.size());
          response.set_auth_tag(encrypted.auth_tag.data(), encrypted.auth_tag.size());
        } else if (request.has_decrypt()) {
          const WorkKey key = key_manager_.key_by_id(request.decrypt().key_id());
          const auto plaintext = aes_256_gcm_decrypt(
              key.material, request.decrypt().nonce(), request.decrypt().ciphertext(),
              request.decrypt().auth_tag());
          response.set_status("OK");
          response.set_key_id(key.key_id);
          response.set_plaintext(plaintext);
        } else {
          throw std::runtime_error("request has no operation");
        }
      } catch (const std::exception& error) {
        response.set_status("ERROR");
        response.set_error(error.what());
      }
    }

    if (!write_frame(pipe, response.SerializeAsString())) {
      break;
    }
  }
}
