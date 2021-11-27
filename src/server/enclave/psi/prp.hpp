#pragma once

#include <array>

#include "common/type_check.hpp"
#include "common/types.hpp"
#include "common/uint128.hpp"
#include "crypto/aes.hpp"

class PRP
{
    std::array<uint8_t, mbedtls::aes::BLOCK_SIZE> ibuf = {0};

    mbedtls::aes aes;

  public:
    using integer = uint128_t;
    using binary = a8<sizeof(integer)>;

    PRP()
    {
        aes.setkey_enc<mbedtls::aes::KEY_LEN_128>({0});
    }

    auto operator()(integer input) -> integer
    {
        *reinterpret_cast<integer*>(ibuf.data()) = input;
        auto obuf = aes.crypt_ecb(ibuf, true);
        return *reinterpret_cast<const integer*>(obuf.data());
    }
};
