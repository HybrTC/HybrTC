# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.
add_custom_command(
  OUTPUT helloworld_u.h helloworld_u.c helloworld_args.h
  DEPENDS ${CMAKE_SOURCE_DIR}/helloworld.edl
  COMMAND
    openenclave::oeedger8r --untrusted ${CMAKE_SOURCE_DIR}/helloworld.edl
    --search-path ${OE_INCLUDEDIR} --search-path
    ${OE_INCLUDEDIR}/openenclave/edl/sgx)

add_executable(helloworld_host host.cpp ocall.c
                               ${CMAKE_CURRENT_BINARY_DIR}/helloworld_u.c)

# Needed for the generated file helloworld_u.h
target_include_directories(helloworld_host PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_include_directories(helloworld_host PRIVATE ${CMAKE_SOURCE_DIR}/common)

target_link_libraries(helloworld_host openenclave::oehost
                      /usr/local/lib/libmbedcrypto.a)
