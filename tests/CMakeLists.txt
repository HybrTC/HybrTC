if (BUID_TEST_CUCKOOHASHING)

  foreach (LEN RANGE 8 21)
    add_executable(cuckoo_hashing_${LEN} cuckoo_hashing.cpp)
    target_link_libraries(cuckoo_hashing_${LEN} nlohmann_json::nlohmann_json
                          spdlog::spdlog ${LIBMBEDCRYPTO})
    target_compile_definitions(cuckoo_hashing_${LEN}
                               PRIVATE PSI_CH_LOG_LENGTH=${LEN})
  endforeach ()

endif ()

add_executable(perf_bloomfilter perf_bloomfilter.cpp)
target_include_directories(
  perf_bloomfilter PRIVATE ${CMAKE_SOURCE_DIR}/src/common
                           ${CMAKE_SOURCE_DIR}/src/server)
target_link_libraries(perf_bloomfilter nlohmann_json::nlohmann_json
                      spdlog::spdlog ${LIBMBEDCRYPTO})

add_executable(perf_cuckoohashing perf_cuckoohashing.cpp)
target_include_directories(
  perf_cuckoohashing PRIVATE ${CMAKE_SOURCE_DIR}/src/common
                             ${CMAKE_SOURCE_DIR}/src/server)
target_link_libraries(perf_cuckoohashing nlohmann_json::nlohmann_json
                      spdlog::spdlog ${LIBMBEDCRYPTO})

add_executable(perf_primitive perf_primitive.cpp)
target_include_directories(
  perf_primitive PRIVATE ${CMAKE_SOURCE_DIR}/src/common
                         ${CMAKE_SOURCE_DIR}/src/server)
target_link_libraries(perf_primitive nlohmann_json::nlohmann_json
                      spdlog::spdlog ${LIBMBEDCRYPTO})

# if (BUILD_TEST_PERF_BLOOMFILTER)

# endif()ssh docker-intel
