#include <cstddef>
#include <cstring>
#include <string>
#include <tuple>
#include <utility>

#include "../msg_pb.h"
#include "common/types.hpp"
#include "config.hpp"
#include "crypto/bignum.hpp"
#include "join_handler.hpp"
#include "sgx/log.h"

using mbedtls::ctr_drbg;
using mbedtls::mpi;

JoinHandler::JoinHandler(sptr<ctr_drbg> rand_ctx) : SelectHandler(std::move(rand_ctx))
{
}

void JoinHandler::load_data(const u32* data_key, const u32* data_val, size_t data_size)
{
    SelectHandler::load_data(data_key, data_val, data_size);

    if (split() == 2)
    {
        size_t mid = local_data.size() / 2;

        left_data.resize(local_data.size() - mid);
        memcpy(u8p(&left_data[0]), u8p(&local_data[mid]), left_data.size() * sizeof(left_data[0]));

        local_data.resize(mid);
    }
    else if (split() != 0)
    {
        // TODO:
        TRACE_ENCLAVE("unimplemented split_shares = %u", split());
        abort();
    }
}

auto JoinHandler::build_filter() -> const std::string&
{
    HashSet bloom_filter(1 << FILTER_POWER_BITS);

    for (auto& [k, _] : local_data)
    {
        bloom_filter.insert(prp(k));
    }

    return bloom_filter.data();
}

auto JoinHandler::match_filter(const std::string& filter) -> std::string
{
    if (split() > 0 && split() != 2)
    {
        // TODO:
        TRACE_ENCLAVE("unimplemented split_shares = %u", split());
        abort();
    }

    HashSet bloom_filter(1 << FILTER_POWER_BITS, filter);

    hybrtc::Pairs hits;

    const database_t& db = split() == 2 ? left_data : local_data;
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
    hybrtc::Pairs peer;
    peer.ParseFromArray(data.data(), static_cast<int>(data.size()));

    /*
     * build cuckoo hashing table
     */
    PRP prp;
    HashTable hashing(1 << CH_LOG_LENGTH, 1 << CH_LOG_DEPTH);

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

auto JoinHandler::get_result() -> std::string
{
#if PSI_AGGREGATE_POLICY == PSI_AGGREAGATE_SELECT
    abort();
#endif

    hybrtc::Pairs result;

#if PSI_AGGREGATE_POLICY == PSI_AGGREAGATE_JOIN_SUM
    for (const auto& [key_bin, peer_bin, this_raw] : intersection)
    {
        mpi peer_val(u8p(peer_bin.data()), peer_bin.size());
        mpi this_val(homo.encrypt(this_raw, *rand_ctx));
        const auto sum = homo.add(peer_val, this_val).to_vector();

        auto* pair = result.add_pairs();
        pair->set_key(key_bin);
        pair->set_value(sum.data(), sum.size());
    }
#else
    auto* pair = result.add_pairs();

    size_t size = intersection.size();
    auto rand = rand_ctx->rand<size_t>();

    pair->set_key(u8p(&size), sizeof(size_t));
    pair->set_value(u8p(&rand), sizeof(size_t));
#endif

    return result.SerializeAsString();
}
