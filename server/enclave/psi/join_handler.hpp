#pragma once

#include "bloom_filter.hpp"
#include "cuckoo_hashing.hpp"
#include "prp.hpp"
#include "select_handler.hpp"

class JoinHandler : public SelectHandler
{
    constexpr static u32 FILTER_POWER_BITS = 24;
    constexpr static u32 NUMBER_OF_HASHES = 4;
    constexpr static u32 CH_LOG_LENGTH = 16;
    constexpr static u32 CH_LOG_DEPTH = 2;

    using HashSet = BloomFilter<FILTER_POWER_BITS, NUMBER_OF_HASHES, PRP::integer>;
    using HashTable = CuckooHashing<CH_LOG_LENGTH, CH_LOG_DEPTH, NUMBER_OF_HASHES>;

    PRP prp;
    bool half_data = false;
    database_t left_data;

  public:
    explicit JoinHandler(sptr<mbedtls::ctr_drbg> rand_ctx);

    void set_half(bool half = true)
    {
        half_data = half;
    }

    void load_data(const u32* data_key, const u32* data_val, size_t data_size) override;

    auto build_filter() -> v8;

    auto match_filter(const v8& filter) -> v8;

    auto aggregate(const v8& data) -> v8;
};
