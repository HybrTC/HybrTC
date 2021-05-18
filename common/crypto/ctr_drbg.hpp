#pragma once

#include <array>

#include "common/types.hpp"
#include "entropy.hpp"
#include "internal/resource.hpp"

namespace mbedtls
{
#include <mbedtls/ctr_drbg.h>

class ctr_drbg : public internal::resource<mbedtls_ctr_drbg_context, mbedtls_ctr_drbg_init, mbedtls_ctr_drbg_free>
{
    entropy ent;

  public:
    explicit ctr_drbg()
    {
        seed({0});
    }

    void seed(const v8& custom)
    {
        mbedtls_ctr_drbg_seed(get(), mbedtls_entropy_func, ent.get(), custom.data(), custom.size());
    }

    template <class I>
    auto rand() -> I
    {
        I num;
        mbedtls_ctr_drbg_random(get(), u8p(&num), sizeof(num));
        return num;
    }

    void fill(u8* buf, size_t len)
    {
        mbedtls_ctr_drbg_random(get(), buf, len);
    }
};

} // namespace mbedtls
