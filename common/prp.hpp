#pragma once

#include <array>

#include "common/type_check.hpp"
#include "common/uint128.hpp"
#include "mbedtls/aes.h"

template <class IntType = uint128_t>
class PRP
{
    INTEGER_CHECK(IntType, "input of PRP");

    std::array<uint8_t, 128 / 8> ibuf = {0};
    std::array<uint8_t, 128 / 8> obuf = {0};

    mbedtls_aes_context aes_ctx;

  public:
    PRP()
    {
        std::array<uint8_t, 128 / 8> key = {0};
        mbedtls_aes_init(&aes_ctx);
        mbedtls_aes_setkey_enc(&aes_ctx, key.data(), 128);
    }

    IntType operator()(IntType input)
    {
        *reinterpret_cast<IntType*>(ibuf.data()) = input;

        mbedtls_aes_crypt_ecb(
            &aes_ctx, MBEDTLS_AES_ENCRYPT, ibuf.data(), &obuf[0]);

        return *reinterpret_cast<const IntType*>(obuf.data());
    }
};
