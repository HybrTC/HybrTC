#pragma once

#include <array>

#include "common/type_check.hpp"
#include "mbedtls/sha1.h"

template <uint32_t hid, class HT = uint32_t, class VT = uint32_t>
class HASH
{
    INTEGER_CHECK(HT, "hash value");
    INTEGER_CHECK(VT, "input value");

    struct
    {
        uint32_t id = hid;
        VT v;
    } msg;

    std::array<uint8_t, 20> hash;

  public:
    HT operator()(VT val)
    {
        msg.v = val;
        mbedtls_sha1_ret((const unsigned char*)&msg, sizeof(msg), &hash[0]);
        return *reinterpret_cast<const HT*>(hash.data());
    }
};
