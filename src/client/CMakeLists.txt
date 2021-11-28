set_source_files_properties(
  ${PROTO_CPP_SRC} PROPERTIES GENERATED 1 COMPILE_OPTIONS
                                          "-Wno-deprecated-declarations")

add_library(TxProtoClient ${PROTO_CPP_SRC})
add_dependencies(TxProtoClient PROTO_CPP_SRC_GENERATE)
target_include_directories(TxProtoClient PRIVATE ${PROTO_CPP_INC})
target_link_libraries(TxProtoClient protobuf::libprotobuf)
target_compile_options(TxProtoClient PRIVATE "-Wno-unused-parameter")

file(
  GLOB
  CLIENT_SRCS
  ${PROTO_CPP_SRC}
  *.cpp
  ${CMAKE_SOURCE_DIR}/src/common/host/socket/socket.cpp
  ${CMAKE_SOURCE_DIR}/src/common/sgx/attestation/verifier.cpp
  ${PROTO_CPP_SRC})

foreach (select_policy IN LISTS PSI_SELECT_POLICY)
  foreach (aggregate_policy IN LISTS PSI_AGGREGATE_POLICY)

    set(target client-${select_policy}-${aggregate_policy})

    add_executable(${target} ${CLIENT_SRCS})

    add_dependencies(${target} TxProtoClient)

    target_include_directories(${target} PRIVATE ${PROTO_CPP_INC})

    # target_compile_options(${target} PRIVATE "-fsanitize=address"
    #                                          "-fno-omit-frame-pointer")
    # target_link_options(${target} PRIVATE "-fsanitize=address"
    #                     "-fno-omit-frame-pointer")

    target_link_libraries(
      ${target}
      openenclave::oehost
      ${LIBMBEDCRYPTO}
      spdlog::spdlog
      nlohmann_json::nlohmann_json
      CLI11::CLI11
      TxProtoClient)

    target_compile_definitions(
      ${target} PUBLIC PSI_SELECT_POLICY=${select_policy}
                       PSI_AGGREGATE_POLICY=${aggregate_policy})

  endforeach ()
endforeach ()
