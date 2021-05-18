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

# Generate key
add_custom_command(
  OUTPUT private.pem public.pem
  COMMAND openssl genrsa -out private.pem -3 3072
  COMMAND openssl rsa -in private.pem -pubout -out public.pem)

foreach (select_policy IN LISTS PSI_SELECT_POLICY)
  foreach (aggregate_policy IN LISTS PSI_AGGREGATE_POLICY)

    set(target enclave/enclave-${select_policy}-${aggregate_policy}.signed)

    # Sign enclave
    add_custom_command(
      OUTPUT ${target}
      DEPENDS enclave enclave/helloworld.conf private.pem
      COMMAND
        openenclave::oesign sign -e
        $<TARGET_FILE:enclave-${select_policy}-${aggregate_policy}> -c
        ${ENCLAVE_CONF} -k private.pem)

    add_custom_target(sign-${select_policy}-${aggregate_policy} ALL
                      DEPENDS ${target})

  endforeach ()
endforeach ()
