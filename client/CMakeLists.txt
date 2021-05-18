file(GLOB CLIENT_SRCS *.cpp)

foreach (select_policy IN LISTS PSI_SELECT_POLICY)
  foreach (aggregate_policy IN LISTS PSI_AGGREGATE_POLICY)

    set(target client-${select_policy}-${aggregate_policy})

    add_executable(${target} ${CLIENT_SRCS})

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
      cppzmq-static
      CLI11::CLI11)

    target_compile_definitions(
      ${target} PUBLIC PSI_SELECT_POLICY=${select_policy}
                       PSI_AGGREGATE_POLICY=${aggregate_policy})

  endforeach ()
endforeach ()
