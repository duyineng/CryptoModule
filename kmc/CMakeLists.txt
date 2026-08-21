find_package(CURL CONFIG REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(Protobuf CONFIG REQUIRED)

set(PROTO_FILE "${PROJECT_SOURCE_DIR}/proto/kmc.proto")
set(PROTO_GENERATED_DIR "${CMAKE_CURRENT_BINARY_DIR}/generated")
file(MAKE_DIRECTORY "${PROTO_GENERATED_DIR}")

add_library(kmc_proto STATIC)
target_link_libraries(kmc_proto PUBLIC protobuf::libprotobuf)
target_include_directories(kmc_proto PUBLIC "${PROTO_GENERATED_DIR}")
protobuf_generate(
  TARGET kmc_proto
  LANGUAGE cpp
  PROTOS "${PROTO_FILE}"
  IMPORT_DIRS "${PROJECT_SOURCE_DIR}/proto"
  PROTOC_OUT_DIR "${PROTO_GENERATED_DIR}"
)

add_library(kmc_core STATIC
  src/config.cpp
  src/crypto.cpp
  src/key_manager.cpp
  src/kms_client.cpp
  src/pipe_protocol.cpp
  src/pipe_server.cpp
)
target_include_directories(kmc_core PUBLIC include)
target_link_libraries(kmc_core
    PUBLIC
    kmc_proto
    CURL::libcurl
    OpenSSL::Crypto
)
target_compile_definitions(kmc_core PRIVATE NOMINMAX WIN32_LEAN_AND_MEAN)

add_executable(kmc src/main.cpp)
target_link_libraries(kmc PRIVATE kmc_core)

add_executable(sdk_demo src/sdk_demo.cpp)
target_link_libraries(sdk_demo PRIVATE kmc_proto)
target_compile_definitions(sdk_demo PRIVATE NOMINMAX WIN32_LEAN_AND_MEAN)

set(KMC_CA_CERT "ca.crt")
set(KMC_CLIENT_CERT "terminal.crt")
set(KMC_CLIENT_KEY "terminal.key")
configure_file(
  "${PROJECT_SOURCE_DIR}/config/kmc.ini.in"
  "${CMAKE_CURRENT_BINARY_DIR}/kmc.ini"
  @ONLY
)

add_custom_command(TARGET kmc POST_BUILD
  COMMAND ${CMAKE_COMMAND} -E copy_if_different
          "${CMAKE_CURRENT_BINARY_DIR}/kmc.ini"
          "$<TARGET_FILE_DIR:kmc>/kmc.ini"
  COMMAND ${CMAKE_COMMAND} -E copy_if_different
          "${PROJECT_SOURCE_DIR}/certs/client/ca.crt"
          "$<TARGET_FILE_DIR:kmc>/ca.crt"
  COMMAND ${CMAKE_COMMAND} -E copy_if_different
          "${PROJECT_SOURCE_DIR}/certs/client/terminal.crt"
          "$<TARGET_FILE_DIR:kmc>/terminal.crt"
  COMMAND ${CMAKE_COMMAND} -E copy_if_different
          "${PROJECT_SOURCE_DIR}/certs/client/terminal.key"
          "$<TARGET_FILE_DIR:kmc>/terminal.key"
)

install(TARGETS kmc sdk_demo RUNTIME DESTINATION bin)
