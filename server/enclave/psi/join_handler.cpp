#include <cstddef>
#include <cstring>
#include <tuple>
#include <utility>

#include <nlohmann/json.hpp>

#include "config.hpp"
#include "crypto/bignum.hpp"
#include "join_handler.hpp"
#include "msg.pb.h"

using mbedtls::ctr_drbg;
using mbedtls::mpi;
using nlohmann::json;

JoinHandler::JoinHandler(sptr<ctr_drbg> rand_ctx) : SelectHandler(std::move(rand_ctx))
{
}

void JoinHandler::load_data(const u32* data_key, const u32* data_val, size_t data_size)
{
    SelectHandler::load_data(data_key, data_val, data_size);

    if (half_data)
    {
        size_t mid = local_data.size() / 2;

        left_data.resize(local_data.size() - mid);
        memcpy(u8p(&left_data[0]), u8p(&local_data[mid]), left_data.size() * sizeof(left_data[0]));

        local_data.resize(mid);
    }
}

auto JoinHandler::build_filter() -> v8
{
    HashSet bloom_filter;

    for (auto& [k, _] : local_data)
    {
        bloom_filter.insert(prp(k));
    }

    return bloom_filter.data();
}

auto JoinHandler::match_filter(const v8& filter) -> std::string
{
    HashSet bloom_filter(filter);

    hybrtc::BloomFilterHits hits;

    const database_t& db = half_data ? left_data : local_data;
    for (const auto& [k, v] : db)
    {
        uint128_t key = prp(k);
        if (bloom_filter.lookup(key))
        {
            auto* pair = hits.add_pairs();

            const auto& key_bin = *reinterpret_cast<const PRP::binary*>(&key);
            pair->set_key(key_bin.data(), key_bin.size());

            auto enc = homo.encrypt(v, *rand_ctx).to_vector();
            pair->set_value(enc.data(), enc.size());
        }
    }

    return hits.SerializeAsString();
}

void JoinHandler::build_result(const v8& data)
{
    hybrtc::BloomFilterHits peer;
    peer.ParseFromArray(data.data(), static_cast<int>(data.size()));

    /*
     * build cuckoo hashing table
     */
    PRP prp;
    HashTable hashing;

    for (auto& [k, v] : local_data)
    {
        hashing.insert(prp(k), v);
    }

    /*
     * match cuckoo hashing table
     */
    for (const auto& pair : peer.pairs())
    {
        const auto& key_bin = pair.key();
        const auto& val_bin = pair.value();

        auto query_result = hashing.lookup(*reinterpret_cast<const uint128_t*>(key_bin.data()));
        for (const auto& val : query_result)
        {
            intersection.emplace_back(std::make_tuple(key_bin, val_bin, val));
        }
    }
}

auto JoinHandler::get_result() -> v8
{
#if PSI_AGGREGATE_POLICY == PSI_AGGREAGATE_SELECT
    abort();
#endif

#if PSI_AGGREGATE_POLICY == PSI_AGGREAGATE_JOIN_SUM
    auto result = json::array();

    for (auto& [key, peer_bin, this_raw] : intersection)
    {
        const auto& key_bin = *reinterpret_cast<const PRP::binary*>(&key);

        mpi peer_val(peer_bin.data(), peer_bin.size());
        mpi this_val(homo.encrypt(this_raw, *rand_ctx));

        result.push_back(json::array({key_bin, homo.add(peer_val, this_val).to_vector()}));
    }
#else
    auto result = json::array({intersection.size(), rand_ctx->rand<size_t>()});
#endif

    return json::to_msgpack(result);
}
