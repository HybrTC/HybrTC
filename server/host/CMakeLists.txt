set_source_files_properties(
  ${PROTO_CPP_SRC} PROPERTIES GENERATED 1 COMPILE_OPTIONS
                                          "-Wno-deprecated-declarations")

add_custom_command(
  OUTPUT helloworld_u.h helloworld_u.c helloworld_args.h
  DEPENDS ${ENCLAVE_EDL}
  COMMAND openenclave::oeedger8r --untrusted ${ENCLAVE_EDL} --search-path
          ${OE_INCLUDEDIR} --search-path ${OE_INCLUDEDIR}/openenclave/edl/sgx)

file(GLOB SERVER_SOURCE_FILES *.cpp
     ${CMAKE_SOURCE_DIR}/common/host/socket/socket.cpp ${PROTO_CPP_SRC})

foreach (select_policy IN LISTS PSI_SELECT_POLICY)
  foreach (aggregate_policy IN LISTS PSI_AGGREGATE_POLICY)

    set(target server-${select_policy}-${aggregate_policy})

    add_executable(${target} ${SERVER_SOURCE_FILES}
                             ${CMAKE_CURRENT_BINARY_DIR}/helloworld_u.c)

    add_dependencies(${target} PROTO_CPP_SRC_GENERATE)

    # Needed for the generated file helloworld_u.h
    target_include_directories(${target} PRIVATE ${CMAKE_CURRENT_BINARY_DIR})

    target_link_libraries(
      ${target} openenclave::oehost ${LIBMBEDCRYPTO} spdlog::spdlog
      nlohmann_json::nlohmann_json CLI11::CLI11)

    target_compile_definitions(
      ${target} PUBLIC PSI_SELECT_POLICY=${select_policy}
                       PSI_AGGREGATE_POLICY=${aggregate_policy})

    # target_compile_options(${target} PRIVATE "-fsanitize=address"
    #                                          "-fno-omit-frame-pointer")

    # target_link_options(${target} PRIVATE "-fsanitize=address"
    #                     "-fno-omit-frame-pointer")

  endforeach ()
endforeach ()
