set(PROTO_SPEC_INC ${CMAKE_SOURCE_DIR}/src/common/proto)
set(PROTO_SPEC_SRC ${PROTO_SPEC_INC}/msg.proto)

set(PROTO_CPP_INC ${CMAKE_BINARY_DIR}/proto)

set(PROTO_CPP_SRC ${PROTO_CPP_INC}/msg.pb.cc ${PROTO_CPP_INC}/msg.pb.h)

find_program(_PROTOBUF_PROTOC protoc)

# Generate CPP files

add_custom_command(OUTPUT ${PROTO_CPP_INC}
                   COMMAND ${CMAKE_COMMAND} -E make_directory ${PROTO_CPP_INC})

add_custom_command(
  OUTPUT ${PROTO_CPP_SRC}
  COMMAND ${_PROTOBUF_PROTOC} ${PROTO_SPEC_SRC} --cpp_out ${PROTO_CPP_INC}
          -I${PROTO_SPEC_INC}
  DEPENDS ${PROTO_SPEC_SRC} ${PROTO_CPP_INC})

add_custom_target(PROTO_CPP_SRC_GENERATE DEPENDS ${PROTO_CPP_SRC})
