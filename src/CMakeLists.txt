include_directories(${CMAKE_CURRENT_SOURCE_DIR}/common ${PROTO_CPP_INC})

add_subdirectory(client)
add_subdirectory(server)

# use python to run in batch

set(targets)
foreach (select_policy IN LISTS PSI_SELECT_POLICY)
  foreach (aggregate_policy IN LISTS PSI_AGGREGATE_POLICY)

    list(APPEND targets client-${select_policy}-${aggregate_policy}
         server-${select_policy}-${aggregate_policy}
         sign-${select_policy}-${aggregate_policy})

  endforeach ()
endforeach ()
