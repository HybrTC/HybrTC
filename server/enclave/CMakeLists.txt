# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

# Use the edger8r to generate C bindings from the EDL file.
add_custom_command(
  OUTPUT helloworld_t.h helloworld_t.c helloworld_args.h
  DEPENDS ${CMAKE_SOURCE_DIR}/helloworld.edl
  COMMAND
    openenclave::oeedger8r --trusted ${CMAKE_SOURCE_DIR}/helloworld.edl
    --search-path ${OE_INCLUDEDIR} --search-path
    ${OE_INCLUDEDIR}/openenclave/edl/sgx)

file(GLOB SOURCE_FILES *.cpp)

add_executable(enclave ${SOURCE_FILES}
                       ${CMAKE_CURRENT_BINARY_DIR}/helloworld_t.c)

target_compile_definitions(enclave PUBLIC OE_API_VERSION=2)

# Need for the generated file helloworld_t.h
target_include_directories(enclave PRIVATE ${CMAKE_CURRENT_BINARY_DIR})

target_link_libraries(
  enclave openenclave::oeenclave openenclave::oecrypto${OE_CRYPTO_LIB}
  openenclave::oelibc openenclave::oelibcxx nlohmann_json::nlohmann_json)
