#include "kms_client.hpp"

#include <curl/curl.h>

#include <memory>
#include <stdexcept>
#include <string>

namespace {

std::size_t write_response(char* data, std::size_t size, std::size_t count, void* user_data) {
  const auto bytes = size * count;
  static_cast<std::string*>(user_data)->append(data, bytes);
  return bytes;
}

std::string curl_error(CURLcode code) {
  return std::string(curl_easy_strerror(code));
}

}  // namespace

KmsClient::KmsClient(const KmcConfig& config) : config_(config) {}

kmc::v1::WorkKeyResponse KmsClient::apply_work_key(
    const std::string& request_id,
    const std::string& algorithm,
    std::uint32_t key_length) {
  kmc::v1::ApplyWorkKeyRequest request;
  request.set_algorithm(algorithm);
  request.set_key_length(key_length);
  return post_protobuf(
      config_.base_url + "/api/v1/work-keys", request_id,
      request.SerializeAsString());
}

kmc::v1::WorkKeyResponse KmsClient::rotate_work_key(
    const std::string& request_id,
    const std::string& current_key_id,
    const std::string& algorithm,
    std::uint32_t key_length) {
  kmc::v1::RotateWorkKeyRequest request;
  request.set_algorithm(algorithm);
  request.set_key_length(key_length);
  return post_protobuf(
      config_.base_url + "/api/v1/work-keys/" + current_key_id + "/rotations",
      request_id, request.SerializeAsString());
}

kmc::v1::WorkKeyResponse KmsClient::post_protobuf(
    const std::string& url,
    const std::string& request_id,
    const std::string& request_body) {
  using CurlHandle = std::unique_ptr<CURL, decltype(&curl_easy_cleanup)>;
  CurlHandle curl(curl_easy_init(), curl_easy_cleanup);
  if (!curl) {
    throw std::runtime_error("curl_easy_init failed");
  }

  std::string response_body;
  char error_buffer[CURL_ERROR_SIZE] = {};
  curl_slist* raw_headers = nullptr;
  raw_headers = curl_slist_append(raw_headers, "Content-Type: application/x-protobuf");
  raw_headers = curl_slist_append(raw_headers, "Accept: application/x-protobuf");
  const std::string request_header = "X-Request-Id: " + request_id;
  raw_headers = curl_slist_append(raw_headers, request_header.c_str());
  std::unique_ptr<curl_slist, decltype(&curl_slist_free_all)> headers(
      raw_headers, curl_slist_free_all);

  curl_easy_setopt(curl.get(), CURLOPT_URL, url.c_str());
  curl_easy_setopt(curl.get(), CURLOPT_POST, 1L);
  curl_easy_setopt(curl.get(), CURLOPT_POSTFIELDS, request_body.data());
  curl_easy_setopt(curl.get(), CURLOPT_POSTFIELDSIZE_LARGE,
                   static_cast<curl_off_t>(request_body.size()));
  curl_easy_setopt(curl.get(), CURLOPT_HTTPHEADER, headers.get());
  curl_easy_setopt(curl.get(), CURLOPT_CAINFO, config_.ca_cert.c_str());
  curl_easy_setopt(curl.get(), CURLOPT_SSLCERT, config_.client_cert.c_str());
  curl_easy_setopt(curl.get(), CURLOPT_SSLKEY, config_.client_key.c_str());
  curl_easy_setopt(curl.get(), CURLOPT_SSL_VERIFYPEER, 1L);
  curl_easy_setopt(curl.get(), CURLOPT_SSL_VERIFYHOST, 2L);
  curl_easy_setopt(curl.get(), CURLOPT_CONNECTTIMEOUT, config_.connect_timeout_seconds);
  curl_easy_setopt(curl.get(), CURLOPT_TIMEOUT, config_.request_timeout_seconds);
  curl_easy_setopt(curl.get(), CURLOPT_WRITEFUNCTION, write_response);
  curl_easy_setopt(curl.get(), CURLOPT_WRITEDATA, &response_body);
  curl_easy_setopt(curl.get(), CURLOPT_ERRORBUFFER, error_buffer);
  curl_easy_setopt(curl.get(), CURLOPT_NOSIGNAL, 1L);

  const CURLcode result = curl_easy_perform(curl.get());
  if (result != CURLE_OK) {
    const std::string detail = error_buffer[0] ? error_buffer : curl_error(result);
    throw std::runtime_error("KMS HTTPS request failed: " + detail);
  }

  long status_code = 0;
  curl_easy_getinfo(curl.get(), CURLINFO_RESPONSE_CODE, &status_code);
  if (status_code < 200 || status_code >= 300) {
    kmc::v1::ErrorResponse error;
    if (error.ParseFromString(response_body)) {
      throw std::runtime_error(
          "KMS returned HTTP " + std::to_string(status_code) + ": " +
          error.code() + " - " + error.message());
    }
    throw std::runtime_error("KMS returned HTTP " + std::to_string(status_code));
  }

  kmc::v1::WorkKeyResponse response;
  if (!response.ParseFromString(response_body)) {
    throw std::runtime_error("invalid protobuf response from KMS");
  }
  return response;
}
