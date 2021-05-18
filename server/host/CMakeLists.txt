# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.
add_custom_command(
  OUTPUT helloworld_u.h helloworld_u.c helloworld_args.h
  DEPENDS ${ENCLAVE_EDL}
  COMMAND openenclave::oeedger8r --untrusted ${ENCLAVE_EDL} --search-path
          ${OE_INCLUDEDIR} --search-path ${OE_INCLUDEDIR}/openenclave/edl/sgx)

file(GLOB SERVER_SOURCE_FILES *.cpp)

foreach (select_policy IN LISTS PSI_SELECT_POLICY)
  foreach (aggregate_policy IN LISTS PSI_AGGREGATE_POLICY)

    set(target server-${select_policy}-${aggregate_policy})

    add_executable(${target} ${SERVER_SOURCE_FILES}
                             ${CMAKE_CURRENT_BINARY_DIR}/helloworld_u.c)

    # Needed for the generated file helloworld_u.h
    target_include_directories(${target} PRIVATE ${CMAKE_CURRENT_BINARY_DIR})

    target_link_libraries(
      ${target}
      openenclave::oehost
      ${LIBMBEDCRYPTO}
      spdlog::spdlog
      nlohmann_json::nlohmann_json
      cppzmq-static
      CLI11::CLI11)

    target_compile_definitions(
      ${target} PRIVATE PSI_SELECT_POLICY=${select_policy}
                        PSI_AGGREGATE_POLICY=${aggregate_policy})

  endforeach ()
endforeach ()
