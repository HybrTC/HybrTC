# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

cmake_minimum_required(VERSION 3.11)

# Setting the cmake compiler when LVI mitigation is not enabled.
# This must be done before the `project` command.
find_program(CMAKE_C_COMPILER clang-8 clang)
find_program(CMAKE_CXX_COMPILER clang++-8 clang++)

project("SGX-PSI" LANGUAGES C CXX)

# Currently the `OpenEnclave` package depends on `project()`.
find_package(OpenEnclave CONFIG REQUIRED)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_CXX_STANDARD 17)
set(OE_CRYPTO_LIB
    mbedtls
    CACHE STRING "Crypto library used by enclaves.")

add_compile_options(-Wall -Wextra -pedantic)

add_subdirectory(enclave)
add_subdirectory(host)

# Generate key
add_custom_command(
  OUTPUT private.pem public.pem
  COMMAND openssl genrsa -out private.pem -3 3072
  COMMAND openssl rsa -in private.pem -pubout -out public.pem)

# Sign enclave
add_custom_command(
  OUTPUT enclave/enclave.signed
  DEPENDS enclave enclave/helloworld.conf private.pem
  COMMAND openenclave::oesign sign -e $<TARGET_FILE:enclave> -c
          ${CMAKE_SOURCE_DIR}/enclave/helloworld.conf -k private.pem)

add_custom_target(sign ALL DEPENDS enclave/enclave.signed)

if ((NOT DEFINED ENV{OE_SIMULATION}) OR (NOT $ENV{OE_SIMULATION}))
  add_custom_target(
    run
    DEPENDS helloworld_host sign
    COMMAND helloworld_host ${CMAKE_BINARY_DIR}/enclave/enclave.signed)
endif ()

add_custom_target(
  simulate
  DEPENDS helloworld_host sign
  COMMAND helloworld_host ${CMAKE_BINARY_DIR}/enclave/enclave.signed --simulate)
