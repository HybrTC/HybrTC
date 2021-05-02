#pragma once

#include <array>
#include <cstdint>
#include <vector>

namespace mbedtls
{
#include <mbedtls/aes.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/ecdsa.h>
#include <mbedtls/ecp.h>
#include <mbedtls/entropy.h>

enum
{
    BITS_PER_BYTE = 8
};

namespace internal
{
template <class T, void (*init)(T*) = nullptr, void (*clean)(T*) = nullptr>
class resource
{
    T ctx;

  public:
    resource()
    {
        if (init != nullptr)
        {
            init(&ctx);
        }
    }

    auto get() -> T*
    {
        return &ctx;
    }

    ~resource()
    {
        if (clean != nullptr)
        {
            clean(&ctx);
        }
    }
};
} // namespace internal

class entropy : public internal::resource<
                    mbedtls_entropy_context,
                    &mbedtls_entropy_init,
                    &mbedtls_entropy_free>
{
};

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

class aes
    : public internal::
          resource<mbedtls_aes_context, &mbedtls_aes_init, &mbedtls_aes_free>
{
  public:
    constexpr static unsigned BLOCK_SIZE = 128 / 8;
    constexpr static unsigned KEY_LEN_128 = 128;
    constexpr static unsigned KEY_LEN_192 = 192;
    constexpr static unsigned KEY_LEN_256 = 256;

    template <unsigned KEYLEN>
    auto setkey_enc(const std::array<uint8_t, KEYLEN / BITS_PER_BYTE>& key)
        -> int
    {
        // KEYLEN in { 128, 192, 256 }
        return mbedtls_aes_setkey_enc(get(), key.data(), KEYLEN);
    }

    auto crypt_ecb(const std::array<uint8_t, BLOCK_SIZE>& ibuf, bool encrypt)
        -> std::array<uint8_t, BLOCK_SIZE>
    {
        std::array<uint8_t, BLOCK_SIZE> obuf;
        mbedtls_aes_crypt_ecb(
            get(),
            encrypt ? MBEDTLS_AES_ENCRYPT : MBEDTLS_AES_DECRYPT,
            ibuf.data(),
            &obuf[0]);
        return obuf;
    }
};

class ecp_keypair : public internal::resource<
                        mbedtls_ecp_keypair,
                        mbedtls_ecp_keypair_init,
                        mbedtls_ecp_keypair_free>
{
};

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
