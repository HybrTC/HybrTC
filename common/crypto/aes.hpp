#pragma once

#include <array>

#include "internal/resource.hpp"

namespace mbedtls
{
#include <mbedtls/aes.h>

class aes : public internal::resource<mbedtls_aes_context, &mbedtls_aes_init, &mbedtls_aes_free>
{
  public:
    constexpr static unsigned BLOCK_SIZE = 128 / 8;
    constexpr static unsigned KEY_LEN_128 = 128;
    constexpr static unsigned KEY_LEN_192 = 192;
    constexpr static unsigned KEY_LEN_256 = 256;

    template <unsigned KEYLEN>
    auto setkey_enc(const std::array<uint8_t, KEYLEN / BITS_PER_BYTE>& key) -> int
    {
        // KEYLEN in { 128, 192, 256 }
        return mbedtls_aes_setkey_enc(get(), key.data(), KEYLEN);
    }

    auto crypt_ecb(const std::array<uint8_t, BLOCK_SIZE>& ibuf, bool encrypt) -> std::array<uint8_t, BLOCK_SIZE>
    {
        std::array<uint8_t, BLOCK_SIZE> obuf;
        mbedtls_aes_crypt_ecb(get(), encrypt ? MBEDTLS_AES_ENCRYPT : MBEDTLS_AES_DECRYPT, ibuf.data(), &obuf[0]);
        return obuf;
    }
};

} // namespace mbedtls
