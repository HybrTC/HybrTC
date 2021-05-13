#pragma once

#include "common/type_check.hpp"
#include "common/types.hpp"
#include "crypto/sha512.hpp"

template <unsigned ON, class OT, class IT>
class HASH
{
    INTEGER_CHECK(IT, "input");
    INTEGER_CHECK(OT, "output");

    constexpr static size_t HASH_BYTES = 512 / 8;

    static_assert(ON <= HASH_BYTES / sizeof(OT), "too many hashes required");

    using M = a8<sizeof(IT)>;
    using H = std::array<OT, ON>;

  public:
    auto operator()(const IT& val) const -> H
    {
        const auto& msg = *reinterpret_cast<const M*>(&val);

        mbedtls::sha512 sha;
        sha.update(msg);
        a8<HASH_BYTES> hash = sha.finish();

        return *reinterpret_cast<const H*>(hash.data());
    }
};
