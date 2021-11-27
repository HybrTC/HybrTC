#pragma once

#include <string>
#include <tuple>

#include "bloom_filter.hpp"
#include "common/message.hpp"
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

    using HashSet = BloomFilter<NUMBER_OF_HASHES, PRP::integer>;
    using HashTable = CuckooHashing<NUMBER_OF_HASHES>;

    PRP prp;
    PSI::Paillier homo;

    uint32_t id;
    uint32_t count;

    using result_t = std::vector<std::tuple<std::string, std::vector<std::string>, u32>>;
    result_t intersection;

    std::vector<std::vector<std::pair<uint128_t, uint32_t>>> data;

  public:
    explicit JoinHandler(sptr<mbedtls::ctr_drbg> rand_ctx);

    void set_public_key(const std::string& pubkey)
    {
        homo.load_pubkey(pubkey);
    }

    void set_id(unsigned server_id)
    {
        id = server_id;
    }

    void set_count(unsigned server_count)
    {
        count = server_count;
    }

    void load_data(const u32* data_key, const u32* data_val, size_t data_size) override;

    auto build_filter() -> std::string;

    auto match_filter(const std::string& input, std::string& output) -> Message::Type;

    void build_result(const std::string& input, std::string& output);

    auto get_result() -> std::string override;
};
