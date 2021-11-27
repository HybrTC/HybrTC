#include <utility>

#include "../msg_pb.h"
#include "common/uint128.hpp"
#include "config.hpp"
#include "melbourne.hpp"
#include "prp.hpp"
#include "select_handler.hpp"

using mbedtls::ctr_drbg;

SelectHandler::SelectHandler(sptr<ctr_drbg> rand_ctx) : rand_ctx(std::move(rand_ctx))
{
}

void SelectHandler::load_data(const u32* data_key, const u32* data_val, size_t data_size)
{
#if PSI_SELECT_POLICY == PSI_SELECT_ALL_PASSTHROUGH
    local_data.reserve(data_size);
    for (size_t i = 0; i < data_size; i++)
    {
        local_data.push_back(std::make_pair(data_key[i], data_val[i]));
    }
#else
    MelbourneShuffle shuffle(rand_ctx);
    local_data = shuffle.shuffle(data_key, data_val, data_size);
#endif
}

auto SelectHandler::get_result() -> std::string
{
#if PSI_AGGREGATE_POLICY == PSI_AGGREAGATE_SELECT
    PRP prp;

    hybrtc::Pairs result;
    for (auto& [k, v] : local_data)
    {
        uint128_t key = prp(k);

        auto* pair = result.add_pairs();
        pair->set_key(&key, sizeof(uint128_t));
        pair->set_value(&v, sizeof(v));
    }

    return result.SerializeAsString();
#else
    abort();
#endif
}
