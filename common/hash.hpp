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

    constexpr static unsigned HASH_BYTES = 512 / 8;

    static_assert(ON <= HASH_BYTES / sizeof(OT), "too many hashes required");

    using H = std::array<OT, ON>;

  public:
    auto operator()(const IT& val) const -> H
    {
        std::array<uint8_t, HASH_BYTES> hash;
        mbedtls_sha512_ret(
            reinterpret_cast<const uint8_t*>(&val), sizeof(val), &hash[0], 0);
        return *reinterpret_cast<const H*>(hash.data());
    }
};
