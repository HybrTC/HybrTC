#pragma once

#include <array>

#include "common/type_check.hpp"
#include "mbedtls/aes.h"

template <class IntType>
class PRF
{
    INTEGER_CHECK(IntType, "input of PRF");

    std::array<uint8_t, 128 / 8> key = {0};
    std::array<uint8_t, 128 / 8> ibuf = {0};
    std::array<uint8_t, 128 / 8> obuf = {0};

  public:
    IntType operator()(IntType input)
    {
        mbedtls_aes_context aes_ctx;

        *reinterpret_cast<IntType*>(ibuf.data()) = input;

        mbedtls_aes_init(&aes_ctx);
        mbedtls_aes_setkey_enc(&aes_ctx, key.data(), 128);
        mbedtls_aes_crypt_ecb(
            &aes_ctx, MBEDTLS_AES_ENCRYPT, ibuf.data(), &obuf[0]);

        return *reinterpret_cast<const IntType*>(obuf.data());
    }
};
