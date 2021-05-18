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

# CLI11
add_subdirectory(3rd-party/CLI11)

# constants

set(PSI_SELECT_ALL_PASSTHROUGH 0x00)
set(PSI_SELECT_ALL_OBLIVIOUS 0x10)
set(PSI_SELECT_ODD_OBLIVIOUS 0x11)
set(PSI_AGGREAGATE_SELECT 0x00)
set(PSI_AGGREAGATE_JOIN_COUNT 0x10)
set(PSI_AGGREAGATE_JOIN_SUM 0x11)

# options

set(PSI_VERBOSE "" ON)

# verbose

if (${PSI_VERBOSE})
  set(PSI_VERBOSE 1)
else ()
  set(PSI_VERBOSE 0)
endif ()

set(PSI_DATA_SET_SIZE_LOG 10;12;14;16;18;20)
message(STATUS "PSI_DATA_SET_SIZE_LOG=${PSI_DATA_SET_SIZE_LOG}")

set(PSI_SELECT_POLICY ${PSI_SELECT_ALL_PASSTHROUGH} ${PSI_SELECT_ALL_OBLIVIOUS}
                      ${PSI_SELECT_ODD_OBLIVIOUS})
message(STATUS "PSI_SELECT_POLICY=${PSI_SELECT_POLICY}")

set(PSI_AGGREGATE_POLICY ${PSI_AGGREAGATE_SELECT} ${PSI_AGGREAGATE_JOIN_COUNT}
                         ${PSI_AGGREAGATE_JOIN_SUM})
message(STATUS "PSI_AGGREGATE_POLICY=${PSI_AGGREGATE_POLICY}")

add_compile_definitions(PSI_VERBOSE=${PSI_VERBOSE})
message(STATUS "PSI_VERBOSE=${PSI_VERBOSE}")

# set(CMAKE_VERBOSE_MAKEFILE ON)

include_directories(${CMAKE_SOURCE_DIR}/common)

add_subdirectory(client)
add_subdirectory(server)
add_subdirectory(tests)

# user cmake to run single test

set(SERVER0_HOST "localhost")
set(SERVER0_PORT_P "5000")
set(SERVER0_PORT_C "5001")
set(SERVER1_HOST "localhost")
set(SERVER1_PORT_P "6000")
set(SERVER1_PORT_C "6001")

foreach (select_policy IN LISTS PSI_SELECT_POLICY)
  foreach (aggregate_policy IN LISTS PSI_AGGREGATE_POLICY)

    set(client
        "${CMAKE_BINARY_DIR}/client/client-${select_policy}-${aggregate_policy}"
    )
    set(server
        "${CMAKE_BINARY_DIR}/server/host/server-${select_policy}-${aggregate_policy}"
    )
    set(enclave
        "${CMAKE_BINARY_DIR}/server/enclave/enclave-${select_policy}-${aggregate_policy}.signed"
    )

    add_custom_target(
      run-${select_policy}-${aggregate_policy}
      DEPENDS ${client} ${server} ${enclave}
      COMMAND
        ${client} "--s0-endpoint=tcp://${SERVER0_HOST}:${SERVER0_PORT_C}"
        "--s1-endpoint=tcp://${SERVER1_HOST}:${SERVER1_PORT_C}" & ${server}
        "--enclave-path=${enclave}" "--server-id=0" "--data-size=10"
        "--client-port=${SERVER0_PORT_C}" "--peer-port=${SERVER0_PORT_P}"
        "--peer-endpoint=tcp://${SERVER1_HOST}:${SERVER1_PORT_P}" & ${server}
        "--enclave-path=${enclave}" "--server-id=1" "--data-size=10"
        "--client-port=${SERVER1_PORT_C}" "--peer-port=${SERVER1_PORT_P}"
        "--peer-endpoint=tcp://${SERVER0_HOST}:${SERVER0_PORT_P}")

  endforeach ()
endforeach ()

# use python to run in batch

set(targets)
foreach (select_policy IN LISTS PSI_SELECT_POLICY)
  foreach (aggregate_policy IN LISTS PSI_AGGREGATE_POLICY)

    list(APPEND targets client-${select_policy}-${aggregate_policy}
         server-${select_policy}-${aggregate_policy}
         sign-${select_policy}-${aggregate_policy})

  endforeach ()
endforeach ()

add_custom_target(
  rundemo
  DEPENDS ${targets}
  COMMAND
    python3 ${CMAKE_SOURCE_DIR}/tests/rundemo.py --binary-dir
    ${CMAKE_BINARY_DIR} --select-policy ${PSI_SELECT_POLICY} --aggregate-policy
    ${PSI_AGGREGATE_POLICY} --data-size ${PSI_DATA_SET_SIZE_LOG} --repeat 1)
