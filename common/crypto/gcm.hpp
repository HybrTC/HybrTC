#pragma once

#include <cstddef>
#include <cstdint>
#include <stdexcept>

#include "common/types.hpp"
#include "crypto/aes.hpp"
#include "crypto/ctr_drbg.hpp"
#include "internal/resource.hpp"

namespace mbedtls
{
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/gcm.h>

template <mbedtls_cipher_id_t cipher, uint32_t keybits>
class gcm : public internal::resource<mbedtls_gcm_context, mbedtls_gcm_init, mbedtls_gcm_free>
{
  public:
    constexpr static size_t IV_LEN = 16;
    constexpr static size_t TAG_LEN = 12;
    constexpr static size_t KEY_BYTES = keybits / BITS_PER_BYTE;

    struct ciphertext
    {
        uint32_t id;
        a8<TAG_LEN> tag;
        a8<IV_LEN> iv;
        uint8_t ciphertext[];
    };

    explicit gcm(const std::array<uint8_t, KEY_BYTES>& key)
    {
        mbedtls_gcm_setkey(get(), cipher, key.data(), keybits);
    }

    auto encrypt_size(size_t ilen) -> size_t
    {
        return ilen + sizeof(ciphertext);
    }

    auto encrypt(const v8& input, ctr_drbg& ctr_drbg) -> v8
    {
        return encrypt(input.data(), input.size(), ctr_drbg);
    }

    auto encrypt(const uint8_t* ibuf, size_t ilen, ctr_drbg& ctr_drbg) -> v8
    {
        v8 output(encrypt_size(ilen), 0);
        encrypt(&output[0], output.size(), ibuf, ilen, ctr_drbg);

        return output;
    }

    template <size_t N>
    auto encrypt(a8<N + sizeof(ciphertext)>& output, const a8<N>& input, ctr_drbg& ctr_drbg)
    {
        output.fill(0);
        encrypt(&output[0], output.size(), input.data(), input.size(), ctr_drbg);
    }

    auto encrypt(uint8_t* obuf, size_t olen, const uint8_t* ibuf, size_t ilen, ctr_drbg& ctr_drbg)
    {
        ciphertext& enc = *reinterpret_cast<ciphertext*>(obuf);

        if (olen < encrypt_size(ilen))
        {
            throw std::length_error("the buffer given is not long enough");
        }

        enc.id = ctr_drbg.rand<decltype(enc.id)>();
        ctr_drbg.fill(enc.iv);

        mbedtls_gcm_crypt_and_tag(
            get(),
            MBEDTLS_GCM_ENCRYPT,
            ilen,
            enc.iv.data(),
            IV_LEN,
            nullptr,
            0,
            ibuf,
            enc.ciphertext,
            TAG_LEN,
            u8p(&enc.tag[0]));
    }

    auto decrypt(const v8& input) -> v8
    {
        return decrypt(input.data(), input.size());
    }

    auto decrypt(const uint8_t* input, size_t input_size) -> v8
    {
        const ciphertext& enc = *reinterpret_cast<const ciphertext*>(input);
        v8 output(input_size - sizeof(ciphertext));

        int result = mbedtls_gcm_auth_decrypt(
            get(),
            output.size(),
            enc.iv.data(),
            IV_LEN,
            nullptr,
            0,
            enc.tag.data(),
            TAG_LEN,
            enc.ciphertext,
            &output[0]);

        if (result != 0)
        {
            output.resize(0);
            switch (result)
            {
                case MBEDTLS_ERR_GCM_AUTH_FAILED:
                    throw std::runtime_error("mbedtls_gcm_auth_decrypt returns "
                                             "MBEDTLS_ERR_GCM_AUTH_FAILED");
                case MBEDTLS_ERR_GCM_BAD_INPUT:
                    throw std::runtime_error("mbedtls_gcm_auth_decrypt returns "
                                             "MBEDTLS_ERR_GCM_BAD_INPUT");
            }
        }

        return output;
    }
};

using aes_gcm_256 = gcm<MBEDTLS_CIPHER_ID_AES, aes::KEY_LEN_256>;

} // namespace mbedtls
