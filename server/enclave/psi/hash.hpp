#pragma once

#include "common/type_check.hpp"
#include "common/types.hpp"
#include "crypto/sha512.hpp"

template <unsigned HashNum, class HashType, class ElemType>
class HASH
{
    INTEGER_CHECK(ElemType, "input");
    INTEGER_CHECK(HashType, "output");

    constexpr static size_t HASH_BYTES = 512 / 8;

    static_assert(HashNum <= HASH_BYTES / sizeof(HashType), "too many hashes required");

    using M = a8<sizeof(ElemType)>;
    using H = std::array<HashType, HashNum>;

  public:
    auto operator()(const ElemType& val) const -> H
    {
        const auto& msg = *reinterpret_cast<const M*>(&val);

        mbedtls::sha512 sha;
        sha.update(msg);
        a8<HASH_BYTES> hash = sha.finish();

        return *reinterpret_cast<const H*>(hash.data());
    }
};
