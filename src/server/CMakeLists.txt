set(OE_CRYPTO_LIB
    mbedtls
    CACHE STRING "Crypto library used by enclaves.")

find_file(
  ENCLAVE_CONF
  NAMES helloworld.conf
  PATHS enclave REQUIRED)

find_file(
  ENCLAVE_EDL
  NAMES helloworld.edl
  PATHS . REQUIRED)

add_subdirectory(enclave)
add_subdirectory(host)

foreach (select_policy IN LISTS PSI_SELECT_POLICY)
  foreach (aggregate_policy IN LISTS PSI_AGGREGATE_POLICY)

    set(target enclave/enclave-${select_policy}-${aggregate_policy}.signed)
    set(prvkey prvkey-${select_policy}-${aggregate_policy}.pem)
    set(pubkey pubkey-${select_policy}-${aggregate_policy}.pem)

    # if (EXISTS ${CMAKE_CURRENT_BINARY_DIR}/${target})
    #   file(REMOVE ${CMAKE_CURRENT_BINARY_DIR}/${target})
    # endif ()

    # Generate key
    add_custom_command(
      OUTPUT ${prvkey} ${pubkey}
      COMMAND openssl genrsa -out ${prvkey} -3 3072
      COMMAND openssl rsa -in ${prvkey} -pubout -out ${pubkey})

    # Sign enclave
    add_custom_command(
      OUTPUT ${target}
      DEPENDS enclave enclave/helloworld.conf ${prvkey}
      COMMAND
        openenclave::oesign sign -e
        $<TARGET_FILE:enclave-${select_policy}-${aggregate_policy}> -c
        ${ENCLAVE_CONF} -k ${prvkey})

    add_custom_target(sign-${select_policy}-${aggregate_policy} ALL
                      DEPENDS ${target})

    add_dependencies(server-${select_policy}-${aggregate_policy}
                     sign-${select_policy}-${aggregate_policy})

  endforeach ()
endforeach ()
