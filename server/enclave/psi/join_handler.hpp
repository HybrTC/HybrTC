#pragma once

#include <tuple>

#include "bloom_filter.hpp"
#include "common/uint128.hpp"
#include "cuckoo_hashing.hpp"
#include "paillier.hpp"
#include "prp.hpp"
#include "select_handler.hpp"

class JoinHandler : public SelectHandler
{
  protected:
    constexpr static u32 FILTER_POWER_BITS = 24;
    constexpr static u32 NUMBER_OF_HASHES = 4;
    constexpr static u32 CH_LOG_LENGTH = 17;
    constexpr static u32 CH_LOG_DEPTH = 2;

    using HashSet = BloomFilter<FILTER_POWER_BITS, NUMBER_OF_HASHES, PRP::integer>;
    using HashTable = CuckooHashing<CH_LOG_LENGTH, CH_LOG_DEPTH, NUMBER_OF_HASHES>;

    PRP prp;
    PSI::Paillier homo;

    bool half_data = false;
    database_t left_data;

    using result_t = std::vector<std::tuple<uint128_t, v8, u32>>;
    result_t intersection;

  public:
    explicit JoinHandler(sptr<mbedtls::ctr_drbg> rand_ctx);

    void set_public_key(const v8& pubkey)
    {
        homo.load_pubkey(pubkey);
    }

    void set_half(bool half = true)
    {
        half_data = half;
    }

    void load_data(const u32* data_key, const u32* data_val, size_t data_size) override;

    auto build_filter() -> const v8&;

    auto match_filter(const v8& filter) -> v8;

    void build_result(const v8& data);

    auto get_result() -> v8 override;
};
