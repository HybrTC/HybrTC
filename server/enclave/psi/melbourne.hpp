#pragma once

#include <utility>

#include "common/types.hpp"
#include "config.hpp"
#include "crypto/ctr_drbg.hpp"
#include "crypto/gcm.hpp"

using database_t = std::vector<std::pair<u32, u32>>;

class MelbourneShuffle
{
    sptr<mbedtls::ctr_drbg> rand_ctx;
    sptr<mbedtls::aes_gcm_256> cipher;

    union plaintext
    {
        struct
        {
            u64 tag;
            u32 key;
            u32 val;
        } r;
        a8<sizeof(u32) * 4> b;

        plaintext(u32 key, u32 val)
        {
            r.tag = 0;
            r.key = key;
            r.val = val;
        }

        void mark()
        {
            r.tag &= ~UINT8_MAX;

#if PSI_SELECT_POLICY == PSI_SELECT_ODD_OBLIVIOUS
            r.tag |= static_cast<uint8_t>(r.val % 2 == 1);
#elif PSI_SELECT_POLICY == PSI_SELECT_ALL_OBLIVIOUS
            r.tag |= 1;
#endif
        }
    };

    constexpr static size_t CIPHERTEXT_SIZE =
        sizeof(u32) + mbedtls::aes_gcm_256::IV_LEN + mbedtls::aes_gcm_256::TAG_LEN + sizeof(plaintext);
    using ciphertext = a8<CIPHERTEXT_SIZE>;

  public:
    explicit MelbourneShuffle(sptr<mbedtls::ctr_drbg> rand_ctx);

    auto dummy_record() -> plaintext
    {
        return plaintext(rand_ctx->rand<u32>(), rand_ctx->rand<u32>());
    }

    static auto read_bucket(const u32* keys, const u32* vals, size_t data_size, size_t bucket_size, size_t offset)
        -> std::vector<plaintext>;

    auto pad_write_bucket(
        size_t bucket_idx,
        std::vector<v8>& private_bucket,
        size_t& t_counter,
        size_t t_bucket_size,
        size_t p_bucket_size,
        ciphertext* t);

    auto shuffle(const u32* keys, const u32* vals, size_t size) -> database_t;
};
