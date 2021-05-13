#pragma once

#include <array>

#include "common/type_check.hpp"
#include "common/uint128.hpp"
#include "crypto/aes.hpp"

template <class IntType = uint128_t>
class PRP
{
    INTEGER_CHECK(IntType, "input of PRP");

    std::array<uint8_t, mbedtls::aes::BLOCK_SIZE> ibuf = {0};

    mbedtls::aes aes;

  public:
    PRP()
    {
        aes.setkey_enc<mbedtls::aes::KEY_LEN_128>({0});
    }

    auto operator()(IntType input) -> IntType
    {
        *reinterpret_cast<IntType*>(ibuf.data()) = input;
        auto obuf = aes.crypt_ecb(ibuf, true);
        return *reinterpret_cast<const IntType*>(obuf.data());
    }
};
