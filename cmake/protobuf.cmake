set(protobuf_source_dir ${CMAKE_SOURCE_DIR}/3rd-party/protobuf)

message(STATUS "protobuf_source_dir=${protobuf_source_dir}")

# read libprotobuf-lite.cmake
find_file(protobuc_lite_cmake_path libprotobuf-lite.cmake
          PATHS ${protobuf_source_dir}/cmake REQUIRED)
message(STATUS "protobuc_lite_cmake_path=${protobuc_lite_cmake_path}")

file(STRINGS ${protobuc_lite_cmake_path} protobuc_lite_cmake
     REGEX "/src/google/protobuf/.*\.(h|cc)")

# read libprotobuf.cmake
find_file(protobuc_cmake_path libprotobuf.cmake
          PATHS ${protobuf_source_dir}/cmake REQUIRED)
message(STATUS "protobuc_cmake_path=${protobuc_cmake_path}")

file(STRINGS ${protobuc_cmake_path} protobuc_cmake
     REGEX "/src/google/protobuf/.*\.(h|cc)")

# generate file list
foreach (X IN LISTS protobuc_lite_cmake protobuc_cmake)
  cmake_language(EVAL CODE "list(APPEND PROTOBUF_SRC ${X})")
endforeach ()

set_source_files_properties(
  ${PROTOBUF_SRC}
  PROPERTIES
    COMPILE_OPTIONS
    "-Wno-unused-parameter;-Wno-sign-compare;-Wno-missing-field-initializers")

set(PROTOBUF_INC ${protobuf_source_dir}/src)

# Build LibProtobuf
add_library(TxLibProtobuf ${PROTOBUF_SRC})
target_include_directories(TxLibProtobuf PRIVATE ${PROTOBUF_INC})
target_link_libraries(TxLibProtobuf openenclave::oelibc openenclave::oelibcxx)
target_compile_definitions(TxLibProtobuf PUBLIC HAVE_PTHREAD)
target_compile_options(
  TxLibProtobuf PRIVATE "-Wno-uninitialized" "-Wno-unused-parameter"
                        "-Wno-sign-compare")
