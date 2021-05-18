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

# options

option(PSI_DATA_SET_SIZE_LOG "" 10)
option(PSI_VERBOSE "" OFF)

option(PSI_SELECT_ALL_PASSTHROUGH "" OFF)
option(PSI_SELECT_ALL_OBLIVIOUS "" OFF)
option(PSI_SELECT_ODD_OBLIVIOUS "" ON)

option(PSI_AGGREAGATE_SELECT "" OFF)
option(PSI_AGGREAGATE_JOIN_SUM "" OFF)
option(PSI_AGGREAGATE_JOIN_SUM "" OFF)

# select policy

if (PSI_SELECT_ALL_PASSTHROUGH)
  set(PSI_SELECT_POLICY 0x00)
endif ()

if (PSI_SELECT_ALL_OBLIVIOUS)
  set(PSI_SELECT_POLICY 0x10)
endif ()

if (PSI_SELECT_ODD_OBLIVIOUS)
  set(PSI_SELECT_POLICY 0x11)
endif ()

# aggregate policy

if (PSI_AGGREAGATE_SELECT)
  set(PSI_AGGREGATE_POLICY 0x00)
endif ()

if (PSI_AGGREAGATE_JOIN_COUNT)
  set(PSI_AGGREGATE_POLICY 0x10)
endif ()

if (PSI_AGGREAGATE_JOIN_SUM)
  set(PSI_AGGREGATE_POLICY 0x11)
endif ()

# generate compile definitions

if (PSI_VERBOSE)
  add_compile_definitions(
    PSI_SELECT_POLICY=${PSI_SELECT_POLICY}
    PSI_AGGREGATE_POLICY=${PSI_AGGREGATE_POLICY}
    PSI_DATA_SET_SIZE_LOG=${PSI_DATA_SET_SIZE_LOG} VERBOSE=1)
else ()
  add_compile_definitions(
    PSI_SELECT_POLICY=${PSI_SELECT_POLICY}
    PSI_AGGREGATE_POLICY=${PSI_AGGREGATE_POLICY}
    PSI_DATA_SET_SIZE_LOG=${PSI_DATA_SET_SIZE_LOG})
endif ()

# set(CMAKE_VERBOSE_MAKEFILE ON)

include_directories(${CMAKE_SOURCE_DIR}/common)

add_subdirectory(server)
add_subdirectory(client)
add_subdirectory(tests)

add_custom_target(
  rundemo
  DEPENDS demo client server sign
  COMMAND demo ${CMAKE_BINARY_DIR})
