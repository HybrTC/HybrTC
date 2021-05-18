#pragma once

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
        uint8_t tag[TAG_LEN];
        uint8_t iv[IV_LEN];
        uint8_t ciphertext[];
    };

    explicit gcm(const std::array<uint8_t, KEY_BYTES>& key)
    {
        mbedtls_gcm_setkey(get(), cipher, key.data(), keybits);
    }

    auto encrypt(const uint8_t* input, size_t input_size, ctr_drbg& ctr_drbg) -> v8
    {
        v8 output(input_size + sizeof(ciphertext), 0);
        ciphertext& enc = *reinterpret_cast<ciphertext*>(&output[0]);

        enc.id = ctr_drbg.rand<decltype(enc.id)>();
        ctr_drbg.fill(enc.iv, IV_LEN);

        mbedtls_gcm_crypt_and_tag(
            get(),
            MBEDTLS_GCM_ENCRYPT,
            input_size,
            enc.iv,
            IV_LEN,
            nullptr,
            0,
            input,
            enc.ciphertext,
            TAG_LEN,
            enc.tag);

        return output;
    }

    auto decrypt(const uint8_t* input, size_t input_size) -> v8
    {
        const ciphertext& enc = *reinterpret_cast<const ciphertext*>(input);
        v8 output(input_size - sizeof(ciphertext));

        int result = mbedtls_gcm_auth_decrypt(
            get(), output.size(), enc.iv, IV_LEN, nullptr, 0, enc.tag, TAG_LEN, enc.ciphertext, &output[0]);

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
