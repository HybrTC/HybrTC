#pragma once

#include <type_traits>

#include <array>

#include "mbedtls/sha1.h"

template <uint32_t hid, class HT = uint32_t, class VT = uint32_t>
class HASH
{
#define INTEGER_CHECK(t, msg) \
    static_assert(std::is_integral<t>::value, msg " must be an integer")

    INTEGER_CHECK(HT, "hash value");
    INTEGER_CHECK(VT, "input value");

#undef INTEGER_CHECK

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
