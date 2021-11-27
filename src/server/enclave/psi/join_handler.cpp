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
#include "msg.pb.h"
#include "sgx/log.h"

using mbedtls::ctr_drbg;
using mbedtls::mpi;

JoinHandler::JoinHandler(sptr<ctr_drbg> rand_ctx) : SelectHandler(std::move(rand_ctx))
{
}

void JoinHandler::load_data(const u32* data_key, const u32* data_val, size_t data_size)
{
    SelectHandler::load_data(data_key, data_val, data_size);

    if (id == 0)
    {
        data.resize(count);
        for (auto& slice : data)
        {
            slice.reserve(local_data.size() / count);
        }

        unsigned slice_id = 0;
        while (!local_data.empty())
        {
            auto [key, val] = local_data.back();
            data[slice_id].emplace_back(prp(key), val);
            local_data.pop_back();
            slice_id = (slice_id + 1) % count;
        }
    }
    else
    {
        auto& slice = data.emplace_back();
        slice.reserve(local_data.size());
        while (!local_data.empty())
        {
            auto [key, val] = local_data.back();
            slice.emplace_back(prp(key), val);
            local_data.pop_back();
        }
    }

#ifdef PSI_VERBOSE

    for (const auto& slice : data)
    {
        TRACE_ENCLAVE("id = %u, slice size = %lu", id, slice.size());
    }

#endif

    if (local_data.empty())
    {
        local_data.shrink_to_fit();
    }
    else
    {
        TRACE_ENCLAVE("Unexpected local_data not empty");
        abort();
    }
}

auto JoinHandler::build_filter() -> std::string
{
    HashSet bloom_filter(1 << FILTER_POWER_BITS);

    for (const auto& [key, _] : data[0])
    {
        bloom_filter.insert(key);
    }

    hybrtc::ComputeRequest request;
    request.set_initiator_id(id);
    request.set_sender_id(id);
    request.set_bloom_filter(bloom_filter.data());

    return request.SerializeAsString();
}

auto JoinHandler::match_filter(const std::string& input, std::string& output) -> Message::Type
{
    hybrtc::ComputeRequest request;
    request.ParseFromString(input);
    assert(request.initiator_id() != id);

    const auto slice_id = (id == 0) ? request.initiator_id() : 0;
#if PSI_VERBOSE
    TRACE_ENCLAVE("[s%u] %s: initiator_id = %u", id, __FUNCTION__, request.initiator_id());
    const auto& slice = data[slice_id];
    TRACE_ENCLAVE("[s%u] @ %s: slice id = %u, slice size = %lu", id, __FUNCTION__, slice_id, slice.size());
#endif

    HashSet bloom_filter(1 << FILTER_POWER_BITS, request.bloom_filter());

    if (request.initiator_id() == (id + 1) % count)
    {
        hybrtc::ComputeResponse result;
        result.set_initiator_id(request.initiator_id());
        result.set_sender_id(id);

        for (const auto& [key, val] : data[slice_id])
        {
            if (bloom_filter.lookup(key))
            {
                auto* pair = result.add_pairs();

                const auto& key_bin = *reinterpret_cast<const PRP::binary*>(&key);
                pair->set_key(key_bin.data(), key_bin.size());

                auto enc = homo.encrypt(val, *rand_ctx).to_vector();
                pair->add_value(enc.data(), enc.size());
            }
        }

        result.SerializeToString(&output);
        return Message::ComputeResponse;
    }

    hybrtc::ComputeRequest result;
    result.set_initiator_id(request.initiator_id());
    result.set_sender_id(id);

    HashSet new_filter(1 << FILTER_POWER_BITS);

    for (const auto& [key, _] : data[slice_id])
    {
        if (bloom_filter.lookup(key))
        {
            new_filter.insert(key);
        }
    }

    result.set_bloom_filter(new_filter.data());
    result.SerializeToString(&output);
    return Message::ComputeRequest;
}

void JoinHandler::build_result(const std::string& input, std::string& output)
{
    hybrtc::ComputeResponse response;
    response.ParseFromString(input);

    const auto slice_id = (id == 0) ? response.initiator_id() : 0;
#if PSI_VERBOSE
    TRACE_ENCLAVE("[s%u] %s: initiator_id = %u", id, __FUNCTION__, response.initiator_id());
    const auto& slice = data[slice_id];
    TRACE_ENCLAVE("[s%u] %s: slice id = %u, slice size = %lu", id, __FUNCTION__, slice_id, slice.size());
#endif

    /*
     * build cuckoo hashing table
     */
    HashTable hashing(1 << CH_LOG_LENGTH, 1 << CH_LOG_DEPTH);
    for (const auto& [key, val] : data[slice_id])
    {
        hashing.insert(key, val);
    }

    if (response.initiator_id() != id)
    {
        hybrtc::ComputeResponse result;
        result.set_initiator_id(response.initiator_id());
        result.set_sender_id(id);

        for (const auto& pair : response.pairs())
        {
            const auto& key_bin = pair.key();

            auto query_result = hashing.lookup(*reinterpret_cast<const uint128_t*>(key_bin.data()));
            for (const auto& val : query_result)
            {
                auto enc = homo.encrypt(val, *rand_ctx).to_vector();

                auto* new_pair = result.add_pairs();
                new_pair->CopyFrom(pair);
                new_pair->add_value(enc.data(), enc.size());
            }
        }

        result.SerializeToString(&output);
    }
    else
    {
        output.clear();
        /*
         * match cuckoo hashing table
         */
        for (const auto& pair : response.pairs())
        {
            const auto& key_bin = pair.key();
            const auto& val_bin = pair.value();

            auto query_result = hashing.lookup(*reinterpret_cast<const uint128_t*>(key_bin.data()));
            for (const auto& val : query_result)
            {
                intersection.emplace_back(
                    std::make_tuple(key_bin, std::vector<std::string>(val_bin.begin(), val_bin.end()), val));
            }
        }
    }
}

auto JoinHandler::get_result() -> std::string
{
#if PSI_AGGREGATE_POLICY == PSI_AGGREAGATE_SELECT
    abort();
#endif

    hybrtc::QueryResponse result;

#if PSI_AGGREGATE_POLICY == PSI_AGGREAGATE_JOIN_SUM
    for (const auto& [key_bin, peer_bins, this_raw] : intersection)
    {
        mpi sum(homo.encrypt(this_raw, *rand_ctx));

        for (const auto& peer_bin : peer_bins)
        {
            mpi peer_val(u8p(peer_bin.data()), peer_bin.size());
            sum = homo.add(sum, peer_val);
        }

        const auto sum_bin = sum.to_vector();

        auto* pair = result.add_pairs();
        pair->set_key(key_bin);
        pair->set_value(sum_bin.data(), sum_bin.size());
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
