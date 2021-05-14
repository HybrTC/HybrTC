#include "melbourne.hpp"

#include <algorithm>
#include <cmath>
#include <limits>
#include <random>
#include <stdexcept>
#include <vector>

#include <openenclave/enclave.h>

#include "common/types.hpp"
#include "config.hpp"
#include "crypto/ctr_drbg.hpp"
#include "crypto/gcm.hpp"
#include "sgx/log.h"

using mbedtls::aes_gcm_256;

extern sptr<mbedtls::ctr_drbg> rand_ctx;

/*
 * pair comparator
 */
template <class F, class S>
auto operator<(const std::pair<F, S>& lhs, const std::pair<F, S>& rhs) -> bool
{
    return lhs.first == rhs.first ? lhs.second < rhs.second
                                  : lhs.first < rhs.first;
}

/*
 * random number generator
 */
class UniformRandomBitGenerator
{
  public:
    // types
    using result_type = size_t;

    // engine characteristics
    static constexpr auto min() -> result_type
    {
        return std::numeric_limits<result_type>::min();
    }

    static constexpr auto max() -> result_type
    {
        return std::numeric_limits<result_type>::max();
    }

    // constructors and seeding functions
    // explicit linear_congruential_engine(result_type s = default_seed);
    // template <class Sseq>
    // explicit linear_congruential_engine(Sseq& q);
    // void seed(result_type s = default_seed);
    // template <class Sseq>
    // void seed(Sseq& q);

    // generating functions
    auto operator()() -> result_type
    {
        return rand_ctx->rand<result_type>();
    };
    // void discard(unsigned long long z);
};

/*
 * cipher generator
 */
auto gen_cipher() -> aes_gcm_256
{
    a8<aes_gcm_256::KEY_BYTES> key;
    oe_random(static_cast<void*>(&key[0]), key.size());
    return aes_gcm_256(key);
}

/*
 * type utils
 */
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

    explicit plaintext()
    {
        r.tag = 0;
        r.key = rand_ctx->rand<u32>();
        r.val = rand_ctx->rand<u32>();
    }

    void mark()
    {
        r.tag &= ~UINT8_MAX;

#ifdef PSI_SELECT_ODD
        r.tag |= r.val & 1;
#endif

#ifdef PSI_SELECT_EVEN
        r.tag |= (~r.val) & 1;
#endif

#ifdef PSI_SELECT_ALL
        r.tag |= 1;
#endif
    }
};

constexpr size_t CIPHERTEXT_SIZE = sizeof(u32) + aes_gcm_256::IV_LEN +
                                   aes_gcm_256::TAG_LEN + sizeof(plaintext);
using ciphertext = a8<CIPHERTEXT_SIZE>;

/*
 * Melbourne Shuffle
 */
auto read_bucket(
    const u32* keys,
    const u32* vals,
    size_t data_size,
    size_t bucket_size,
    size_t offset) -> std::vector<plaintext>
{
    std::vector<plaintext> read_in;
    read_in.reserve(bucket_size);
    for (size_t idx_d = offset; idx_d < data_size; idx_d++)
    {
        if (read_in.size() < bucket_size)
        {
            read_in.emplace_back(keys[idx_d], vals[idx_d]);
        }
        else
        {
            break;
        }
    }
    return read_in;
}

auto pad_write_bucket(
    size_t bucket_idx,
    std::vector<v8>& private_bucket,
    size_t& t_counter,
    size_t t_bucket_size,
    size_t p_bucket_size,
    aes_gcm_256& cipher,
    ciphertext* t)
{
    /* check if the shuffle fails */
    if (t_counter + private_bucket.size() > t_bucket_size)
    {
        TRACE_ENCLAVE("melbourne_shuffle: overwrite a bucket "
                      "in intermediate memory");
        throw std::range_error("melbourne_shuffle: overwrite a bucket "
                               "in intermediate memory");
    }

    if (private_bucket.size() > p_bucket_size)
    {
        TRACE_ENCLAVE("melbourne_shuffle: overwrite a bucket "
                      "in private memory");
    }

    /* padding with dummy data */
    while (private_bucket.size() < p_bucket_size)
    {
        plaintext o;
        auto enc = cipher.encrypt(o.b.data(), o.b.size(), *rand_ctx);
        private_bucket.push_back(enc);
    }

    /* write out */
    size_t base = t_bucket_size * bucket_idx;
    for (const auto& enc : private_bucket)
    {
        if (enc.size() != CIPHERTEXT_SIZE)
        {
            throw std::length_error("unexpected ciphertext length");
        }

        auto& target = t[base + t_counter++];
        std::copy(enc.begin(), enc.end(), target.begin());
    }
}

auto melbourne_shuffle(const u32* keys, const u32* vals, size_t data_size)
    -> database_t
{
    /*
     * split the input array
     *
     * I            = sqrt(N) buckets
     * bucket       = N / sqrt(N) elements
     */
    auto bucket_cnt = size_t(std::ceill(sqrt(data_size)));
    auto bucket_size = (data_size + bucket_cnt - 1) / bucket_cnt;

    /*
     * construct the intermediate array
     *
     * p_bucket_size <= p * log(N)
     * t_bucket_size <= p * log(N) * sqrt(N)
     * t_size        <= p * log(N) * sqrt(N) * sqrt(N) = p * log(N) * N
     */
    auto p_bucket_size = size_t(std::ceil(PSI_MELBOURNE_P * log2(data_size)));
    auto t_bucket_size = p_bucket_size * bucket_cnt;
    auto t_size = t_bucket_size * bucket_cnt;

    /* allocate external memory */
    auto* t =
        reinterpret_cast<ciphertext*>(oe_host_malloc(t_size * CIPHERTEXT_SIZE));

    /*
     * initialize prng and cipher
     */
    std::uniform_int_distribution<size_t> dist(0, t_size);
    UniformRandomBitGenerator urbg;
    auto cipher = gen_cipher();

    /************************************************************
     * Distribution Phase                                       *
     ************************************************************/
    std::vector<size_t> t_counter(bucket_cnt, 0);

    for (size_t idx_b = 0; idx_b < bucket_cnt; idx_b++)
    {
        if ((idx_b & 0xf) == 0)
        {
            TRACE_ENCLAVE(
                "%s: distribution phase %lu/%lu",
                __FUNCTION__,
                idx_b,
                bucket_cnt);
        }

        /* read a bucket of data */
        std::vector<plaintext> read_in = read_bucket(
            keys, vals, data_size, bucket_size, idx_b * bucket_size);

        /* prepare private memory */
        std::vector<std::vector<v8>> private_memory(bucket_cnt);

        /* mark and shuffle */
        for (auto& item : read_in)
        {
            item.mark();
            item.r.tag |= dist(urbg) << sizeof(u8);

            size_t bucket_idx = (item.r.tag >> sizeof(u8)) % bucket_cnt;
            auto enc = cipher.encrypt(item.b.data(), item.b.size(), *rand_ctx);
            private_memory[bucket_idx].push_back(enc);
        }

        /* clear previously read data to release the enclave memory */
        read_in.clear();

        /* pad and write */
        for (size_t bucket_idx = 0; bucket_idx < bucket_cnt; bucket_idx++)
        {
            pad_write_bucket(
                bucket_idx,
                private_memory[bucket_idx],
                t_counter[bucket_idx],
                t_bucket_size,
                p_bucket_size,
                cipher,
                t);
        }

        private_memory.clear();
    }

    for (auto cnt : t_counter)
    {
        if (cnt != t_bucket_size)
        {
            throw std::length_error(
                "unexpected final bucket size in intermediate array");
        }
    }

    /***********************************************************
     * Clean-up Phase                                          *
     ***********************************************************/

    std::vector<std::pair<u64, std::pair<u32, u32>>> result;
    for (size_t i = 0; i < t_size; i++)
    {
        auto msg = cipher.decrypt(t[i].data(), t[i].size());
        const plaintext& obj = *reinterpret_cast<const plaintext*>(msg.data());
        if ((obj.r.tag & UINT8_MAX) > 0)
        {
            result.emplace_back(std::make_pair(
                obj.r.tag >> sizeof(u8), std::make_pair(obj.r.key, obj.r.val)));
        }
    }
    std::sort(result.begin(), result.end());

    /* free external memory */
    oe_host_free(t);

    database_t database;
    for (auto&& [_, data] : result)
    {
        database.push_back(data);
    }

    return database;
}