#pragma once

#include <array>

#include "entropy.hpp"
#include "internal/resource.hpp"

namespace mbedtls
{
#include <mbedtls/ctr_drbg.h>

class ctr_drbg : public internal::resource<
                     mbedtls_ctr_drbg_context,
                     mbedtls_ctr_drbg_init,
                     mbedtls_ctr_drbg_free>
{
    entropy ent;

  public:
    explicit ctr_drbg()
    {
        std::array<uint8_t, MBEDTLS_CTR_DRBG_KEYSIZE> custom = {0};
        // oe_random(&custom[0], custom.size());

        mbedtls_ctr_drbg_seed(
            get(),
            mbedtls_entropy_func,
            ent.get(),
            custom.data(),
            custom.size());
    }
};

} // namespace mbedtls
