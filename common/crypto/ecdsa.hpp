#pragma once

#include <vector>

#include "ctr_drbg.hpp"
#include "internal/resource.hpp"

namespace mbedtls
{
#include <mbedtls/ecdsa.h>

class ecdsa : public internal::resource<
                  mbedtls_ecdsa_context,
                  mbedtls_ecdsa_init,
                  mbedtls_ecdsa_free>
{
  public:
    auto genkey(mbedtls_ecp_group_id grp, ctr_drbg& ctr_drbg) -> int
    {
        return mbedtls_ecdsa_genkey(
            get(), grp, mbedtls_ctr_drbg_random, ctr_drbg.get());
    }

    auto dump_pubkey(bool compressed) -> std::vector<uint8_t>
    {
        std::vector<uint8_t> buf(MBEDTLS_ECP_MAX_BYTES, 0);
        size_t len = 0;

        mbedtls_ecp_point_write_binary(
            &get()->grp,
            &get()->Q,
            compressed ? MBEDTLS_ECP_PF_COMPRESSED
                       : MBEDTLS_ECP_PF_UNCOMPRESSED,
            &len,
            &buf[0],
            buf.size());

        buf.resize(len);
        return buf;
    }

    auto sign(
        const mbedtls_md_type_t& type,
        const std::vector<uint8_t>& hash,
        ctr_drbg& ctr_drbg) -> std::vector<uint8_t>
    {
        std::vector<uint8_t> sig(MBEDTLS_ECDSA_MAX_LEN, 0);
        size_t sig_len;

        mbedtls_ecdsa_write_signature(
            get(),
            type,
            hash.data(),
            hash.size(),
            &sig[0],
            &sig_len,
            mbedtls_ctr_drbg_random,
            ctr_drbg.get());

        sig.resize(sig_len);
        return sig;
    }
};
} // namespace mbedtls
