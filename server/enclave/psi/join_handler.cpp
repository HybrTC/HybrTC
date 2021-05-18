#include <cstring>
#include <utility>

#include <nlohmann/json.hpp>

#include "crypto/bignum.hpp"
#include "join_handler.hpp"

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

auto JoinHandler::match_filter(const v8& filter) -> v8
{
    HashSet bloom_filter(filter);
    auto hits = json::array();

    database_t& db = half_data ? left_data : local_data;
    for (auto& [k, v] : db)
    {
        uint128_t key = prp(k);
        if (bloom_filter.lookup(key))
        {
            auto enc = homo.encrypt(v, *rand_ctx).to_vector();
            assert(!enc.empty());

            hits.push_back(json::array({*reinterpret_cast<const PRP::binary*>(&key), enc}));
        }
    }

    return json::to_msgpack(hits);
}

auto JoinHandler::aggregate(const v8& data) -> v8
{
    auto peer = json::from_msgpack(data);

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
     * aggregate calculation
     */

    auto result = json::array();
    for (const auto& pair : peer)
    {
        PRP::binary key_bin = pair[0];
        v8 val_bin = pair[1];

        const uint128_t& key = *reinterpret_cast<const uint128_t*>(key_bin.data());
        mpi peer_val(val_bin.data(), val_bin.size());

        auto query_result = hashing.lookup(key);

        for (auto val : query_result)
        {
#ifdef PSI_JOIN_COUNT
            result.push_back(val);
#else
            result.push_back(json::array({pair[0], homo.add(peer_val, homo.encrypt(val, *rand_ctx)).to_vector()}));
#endif
        }
    }

#ifdef PSI_JOIN_COUNT
    auto ret = json::array({result.size(), rand_ctx->rand<size_t>()});
    return json::to_msgpack(ret);
#else
    return json::to_msgpack(result);
#endif
}