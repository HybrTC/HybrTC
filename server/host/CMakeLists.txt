# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.
add_custom_command(
  OUTPUT helloworld_u.h helloworld_u.c helloworld_args.h
  DEPENDS ${ENCLAVE_EDL}
  COMMAND openenclave::oeedger8r --untrusted ${ENCLAVE_EDL} --search-path
          ${OE_INCLUDEDIR} --search-path ${OE_INCLUDEDIR}/openenclave/edl/sgx)

file(GLOB SERVER_SOURCE_FILES *.cpp)

add_executable(server ${SERVER_SOURCE_FILES}
                      ${CMAKE_CURRENT_BINARY_DIR}/helloworld_u.c)

# Needed for the generated file helloworld_u.h
target_include_directories(server PRIVATE ${CMAKE_CURRENT_BINARY_DIR})

target_link_libraries(
  server
  openenclave::oehost
  ${LIBMBEDCRYPTO}
  spdlog::spdlog
  nlohmann_json::nlohmann_json
  cppzmq-static
  CLI11::CLI11)
