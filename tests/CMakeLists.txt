add_executable(demo demo.cpp)
target_compile_definitions(demo PRIVATE BINARY_DIR=${CMAKE_BINARY_DIR})
target_link_libraries(demo PRIVATE CLI11::CLI11)

add_executable(clocks_per_sec clocks_per_sec.cpp)

if (BUID_TEST_CUCKOOHASHING)

  foreach (LEN RANGE 8 21)
    add_executable(cuckoo_hashing_${LEN} cuckoo_hashing.cpp)
    target_link_libraries(cuckoo_hashing_${LEN} nlohmann_json::nlohmann_json
                          spdlog::spdlog ${LIBMBEDCRYPTO})
    target_compile_definitions(cuckoo_hashing_${LEN}
                               PRIVATE PSI_CH_LOG_LENGTH=${LEN})
  endforeach ()

endif ()
