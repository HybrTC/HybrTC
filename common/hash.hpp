#pragma once

#include <array>
#include <cstdint>

#include "common/type_check.hpp"
#include "common/uint128.hpp"
#include "mbedtls/sha512.h"

template <unsigned ON, class OT = uint32_t, class IT = uint128_t>
class HASH
{
    INTEGER_CHECK(IT, "input");
    INTEGER_CHECK(OT, "output");

    static_assert(ON <= 512 / 8 / sizeof(OT), "too many hashes required");

    using H = const std::array<OT, ON>;

    std::array<uint8_t, 512 / 8> hash;

  public:
    H operator()(const IT& val)
    {
        mbedtls_sha512_ret((const uint8_t*)&val, sizeof(val), &hash[0], 0);
        return *reinterpret_cast<const H*>(hash.data());
    }
};
