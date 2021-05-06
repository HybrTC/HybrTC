#pragma once

#include <mbedtls/ctr_drbg.h>
#include <array>
#include <cstddef>
#include <vector>

#include "common/types.hpp"
#include "ctr_drbg.hpp"
#include "internal/resource.hpp"

namespace mbedtls
{
#include <mbedtls/ecdh.h>

class ecdh
    : public internal::
          resource<mbedtls_ecdh_context, mbedtls_ecdh_init, mbedtls_ecdh_free>
{
  public:
    explicit ecdh(mbedtls_ecp_group_id grp_id)
    {
        mbedtls_ecdh_setup(get(), grp_id);
    }

    auto make_public(ctr_drbg& ctr_drbg) -> v8
    {
        v8 buf(MBEDTLS_ECP_MAX_BYTES, 0);
        size_t len;

        mbedtls_ecdh_make_public(
            get(),
            &len,
            &buf[0],
            buf.size(),
            mbedtls_ctr_drbg_random,
            ctr_drbg.get());

        buf.resize((len));
        return buf;
    }

    void read_public(const v8& buf)
    {
        mbedtls_ecdh_read_public(get(), buf.data(), buf.size());
    }

    auto calc_secret(ctr_drbg& ctr_drbg) -> v8
    {
        v8 buf(MBEDTLS_ECP_MAX_BYTES, 0);
        size_t len;

        mbedtls_ecdh_calc_secret(
            get(),
            &len,
            &buf[0],
            buf.size(),
            mbedtls_ctr_drbg_random,
            ctr_drbg.get());

        buf.resize(len);
        return buf;
    }
};
} // namespace mbedtls
