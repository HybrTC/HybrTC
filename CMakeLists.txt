# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

cmake_minimum_required(VERSION 3.18)

# Setting the cmake compiler when LVI mitigation is not enabled.
# This must be done before the `project` command.
find_program(CMAKE_C_COMPILER clang-8 clang)
find_program(CMAKE_CXX_COMPILER clang++-8 clang++)

project("SGX-PSI" LANGUAGES C CXX)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_CXX_STANDARD 17)
add_compile_options(-O3 -Wall -Wextra)

# Currently the `OpenEnclave` package depends on `project()`.
find_package(OpenEnclave CONFIG REQUIRED)
find_library(LIBMBEDCRYPTO mbedcrypto REQUIRED)

# spdlog
add_subdirectory(3rd-party/spdlog)

# json
set(JSON_BuildTests
    OFF
    CACHE INTERNAL "")
set(JSON_Install
    OFF
    CACHE INTERNAL "")
add_subdirectory(3rd-party/json)

# zeromq
set(ZMQ_BUILD_TESTS
    OFF
    CACHE BOOL "")
set(BUILD_SHARED
    OFF
    CACHE BOOL "")
set(ENABLE_DRAFTS
    OFF
    CACHE BOOL "")
set(ENABLE_CURVE
    OFF
    CACHE BOOL "")
set(WITH_PERF_TOOL
    OFF
    CACHE BOOL "")
set(CPPZMQ_BUILD_TESTS
    OFF
    CACHE BOOL "")
add_subdirectory(3rd-party/libzmq)
add_subdirectory(3rd-party/cppzmq)

include_directories(${CMAKE_SOURCE_DIR}/common)

add_subdirectory(server)
add_subdirectory(client)
add_subdirectory(tests)

add_custom_target(
  rundemo
  DEPENDS demo client server sign
  COMMAND demo ${CMAKE_BINARY_DIR})

set(SERVER0_PORT_P 5000)
set(SERVER0_PORT_C 5001)
set(SERVER1_PORT_P 6000)
set(SERVER1_PORT_C 6001)

add_custom_target(
  runs0
  DEPENDS server sign
  COMMAND
    server 0 ${SERVER0_PORT_C} ${SERVER0_PORT_P}
    tcp://localhost:${SERVER1_PORT_P}
    ${CMAKE_BINARY_DIR}/server/enclave/enclave.signed)

add_custom_target(
  runs1
  DEPENDS server sign
  COMMAND
    server 1 ${SERVER1_PORT_C} ${SERVER1_PORT_P}
    tcp://localhost:${SERVER0_PORT_P}
    ${CMAKE_BINARY_DIR}/server/enclave/enclave.signed)

add_custom_target(
  runc
  DEPENDS client
  COMMAND client tcp://localhost:${SERVER0_PORT_C}
          tcp://localhost:${SERVER1_PORT_C})
