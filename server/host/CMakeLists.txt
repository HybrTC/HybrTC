# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.
add_custom_command(
  OUTPUT helloworld_u.h helloworld_u.c helloworld_args.h
  DEPENDS ${CMAKE_SOURCE_DIR}/helloworld.edl
  COMMAND
    openenclave::oeedger8r --untrusted ${CMAKE_SOURCE_DIR}/helloworld.edl
    --search-path ${OE_INCLUDEDIR} --search-path
    ${OE_INCLUDEDIR}/openenclave/edl/sgx)

file(GLOB SOURCE_FILES *.cpp)

add_executable(helloworld_host ${SOURCE_FILES}
                               ${CMAKE_CURRENT_BINARY_DIR}/helloworld_u.c)

# Needed for the generated file helloworld_u.h
target_include_directories(helloworld_host PRIVATE ${CMAKE_CURRENT_BINARY_DIR})

target_link_libraries(helloworld_host openenclave::oehost ${LIBMBEDCRYPTO}
                      nlohmann_json::nlohmann_json cppzmq)
