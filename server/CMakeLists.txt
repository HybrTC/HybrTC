set(OE_CRYPTO_LIB
    mbedtls
    CACHE STRING "Crypto library used by enclaves.")

find_file(
  ENCLAVE_CONF
  NAMES helloworld.conf
  PATHS enclave REQUIRED)

add_subdirectory(enclave)
add_subdirectory(host)

# Generate key
add_custom_command(
  OUTPUT private.pem public.pem
  COMMAND openssl genrsa -out private.pem -3 3072
  COMMAND openssl rsa -in private.pem -pubout -out public.pem)

# Sign enclave
add_custom_command(
  OUTPUT enclave/enclave.signed
  DEPENDS enclave enclave/helloworld.conf private.pem
  COMMAND openenclave::oesign sign -e $<TARGET_FILE:enclave> -c ${ENCLAVE_CONF}
          -k private.pem)

add_custom_target(sign ALL DEPENDS enclave/enclave.signed)
