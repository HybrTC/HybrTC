include(${CMAKE_SOURCE_DIR}/cmake/protobuf.cmake)

set_source_files_properties(
  ${PROTO_CPP_SRC} PROPERTIES GENERATED 1 COMPILE_OPTIONS
                                          "-Wno-deprecated-declarations")

# Use the edger8r to generate C bindings from the EDL file.
add_custom_command(
  OUTPUT helloworld_t.h helloworld_t.c helloworld_args.h
  DEPENDS ${ENCLAVE_EDL}
  COMMAND openenclave::oeedger8r --trusted ${ENCLAVE_EDL} --search-path
          ${OE_INCLUDEDIR} --search-path ${OE_INCLUDEDIR}/openenclave/edl/sgx)

file(GLOB ENCLAVE_SOURCE_FILES ${PROTO_CPP_SRC} *.cpp psi/*.cpp
     ${CMAKE_SOURCE_DIR}/common/sgx/attestation/*.cpp)

foreach (select_policy IN LISTS PSI_SELECT_POLICY)
  foreach (aggregate_policy IN LISTS PSI_AGGREGATE_POLICY)

    set(target enclave-${select_policy}-${aggregate_policy})

    add_executable(${target} ${ENCLAVE_SOURCE_FILES}
                             ${CMAKE_CURRENT_BINARY_DIR}/helloworld_t.c)

    add_dependencies(${target} PROTO_CPP_SRC_GENERATE)

    target_compile_definitions(
      ${target} PUBLIC OE_API_VERSION=2 PSI_SELECT_POLICY=${select_policy}
                       PSI_AGGREGATE_POLICY=${aggregate_policy})

    # Need for the generated file helloworld_t.h
    target_include_directories(
      ${target} PRIVATE ${CMAKE_CURRENT_BINARY_DIR} ${PROTOBUF_INC}
                        ${PROTO_CPP_INC})

    target_link_libraries(
      ${target}
      openenclave::oeenclave
      openenclave::oecrypto${OE_CRYPTO_LIB}
      openenclave::oelibc
      openenclave::oelibcxx
      nlohmann_json::nlohmann_json
      TxLibProtobuf)

  endforeach ()
endforeach ()
