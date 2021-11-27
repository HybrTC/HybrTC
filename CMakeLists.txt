# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

cmake_minimum_required(VERSION 3.18)

# Setting the cmake compiler when LVI mitigation is not enabled.
# This must be done before the `project` command.
find_program(CMAKE_C_COMPILER clang-10 clang)
find_program(CMAKE_CXX_COMPILER clang++-10 clang++)

project("HybrTC" LANGUAGES C CXX)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

set(CMAKE_CXX_STANDARD 17)

add_compile_options(-Og -g -Wall -Wextra)
# add_compile_options(-O3)

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

# CLI11
add_subdirectory(3rd-party/CLI11)

find_package(Protobuf CONFIG REQUIRED)
message(STATUS "Using protobuf ${Protobuf_VERSION}")
include(cmake/spec.cmake)

# constants

set(PSI_SELECT_ALL_PASSTHROUGH 0x00)
set(PSI_SELECT_ALL_OBLIVIOUS 0x10)
set(PSI_SELECT_ODD_OBLIVIOUS 0x11)
set(PSI_AGGREAGATE_SELECT 0x00)
set(PSI_AGGREAGATE_JOIN_COUNT 0x10)
set(PSI_AGGREAGATE_JOIN_SUM 0x11)

# options

# set(PSI_DATA_SET_SIZE_LOG 10;12;14;16;18;20)

set(PSI_SELECT_POLICY ${PSI_SELECT_ALL_PASSTHROUGH} ${PSI_SELECT_ALL_OBLIVIOUS}
                      ${PSI_SELECT_ODD_OBLIVIOUS})

set(PSI_AGGREGATE_POLICY ${PSI_AGGREAGATE_SELECT} ${PSI_AGGREAGATE_JOIN_COUNT}
                         ${PSI_AGGREAGATE_JOIN_SUM})

set(PSI_VERBOSE "" OFF)
set(PSI_DATA_SET_SIZE_LOG 12)
# set(PSI_SELECT_POLICY ${PSI_SELECT_ODD_OBLIVIOUS})
# set(PSI_AGGREGATE_POLICY ${PSI_AGGREAGATE_JOIN_COUNT})

if (${PSI_VERBOSE})
  add_compile_definitions(PSI_VERBOSE=1)
  message(STATUS "PSI_VERBOSE=1")
else ()
  add_compile_definitions(PSI_VERBOSE=0)
  message(STATUS "PSI_VERBOSE=0")
endif ()

message(STATUS "PSI_DATA_SET_SIZE_LOG=${PSI_DATA_SET_SIZE_LOG}")
message(STATUS "PSI_SELECT_POLICY=${PSI_SELECT_POLICY}")
message(STATUS "PSI_AGGREGATE_POLICY=${PSI_AGGREGATE_POLICY}")

# set(CMAKE_VERBOSE_MAKEFILE ON)

add_subdirectory(src)
add_subdirectory(tests)

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
    python3.8 ${CMAKE_SOURCE_DIR}/tests/rundemo.py --binary-dir
    ${CMAKE_BINARY_DIR} --select-policy ${PSI_SELECT_POLICY} --aggregate-policy
    ${PSI_AGGREGATE_POLICY} --data-size ${PSI_DATA_SET_SIZE_LOG} --repeat 1)
