#pragma once

#include <vector>

#include "crypto/ctr_drbg.hpp"
#include "internal/resource.hpp"
#include "log.h"

namespace mbedtls
{
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/gcm.h>

template <mbedtls_cipher_id_t cipher, uint32_t keybits>
class gcm
    : public internal::
          resource<mbedtls_gcm_context, &mbedtls_gcm_init, &mbedtls_gcm_free>
{
    constexpr static size_t IV_LEN = 12;
    constexpr static size_t TAG_LEN = 12;

    struct ciphertext
    {
        uint8_t iv[IV_LEN];
        uint8_t tag[TAG_LEN];
        uint8_t ciphertext[];
    };

  public:
    explicit gcm(const std::array<uint8_t, keybits / BITS_PER_BYTE>& key)
    {
        mbedtls_gcm_setkey(get(), cipher, key.data(), keybits);
    }

    auto encrypt(const std::vector<uint8_t>& input, ctr_drbg& ctr_drbg)
        -> std::vector<uint8_t>
    {
        return encrypt(input.data(), input.size(), ctr_drbg);
    }

    auto encrypt(const std::vector<uint32_t>& input, ctr_drbg& ctr_drbg)
        -> std::vector<uint8_t>
    {
        return encrypt(
            reinterpret_cast<const uint8_t*>(input.data()),
            input.size() * sizeof(uint32_t),
            ctr_drbg);
    }

    auto encrypt(const uint8_t* input, size_t input_size, ctr_drbg& ctr_drbg)
        -> std::vector<uint8_t>
    {
        std::vector<uint8_t> output(input_size + sizeof(ciphertext), 0);
        ciphertext& enc = *reinterpret_cast<ciphertext*>(&output[0]);

        mbedtls_ctr_drbg_random(ctr_drbg.get(), enc.iv, IV_LEN);

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

    auto decrypt(const std::vector<uint8_t>& input) -> std::vector<uint8_t>
    {
        const ciphertext& enc = *reinterpret_cast<const ciphertext*>(&input[0]);
        std::vector<uint8_t> output(input.size() - sizeof(ciphertext));

        int result = mbedtls_gcm_auth_decrypt(
            get(),
            output.size(),
            enc.iv,
            IV_LEN,
            nullptr,
            0,
            enc.tag,
            TAG_LEN,
            enc.ciphertext,
            &output[0]);

        if (result != 0)
        {
            TRACE_ENCLAVE("mbedtls_gcm_auth_decrypt -> -0x%x", -result);
            output.resize(0);
        }

        return output;
    }
};

} // namespace mbedtls
