file(GLOB SOURCE_FILES *.cpp)

add_executable(client ${SOURCE_FILES})

target_link_libraries(client openenclave::oehost ${LIBMBEDCRYPTO}
                      spdlog::spdlog nlohmann_json::nlohmann_json cppzmq)
