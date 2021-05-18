#include <utility>

#include <nlohmann/json.hpp>

#include "config.hpp"
#include "melbourne.hpp"
#include "prp.hpp"
#include "select_handler.hpp"

using mbedtls::ctr_drbg;
using nlohmann::json;

SelectHandler::SelectHandler(sptr<ctr_drbg> rand_ctx) : rand_ctx(std::move(rand_ctx))
{
}

void SelectHandler::load_data(const u32* data_key, const u32* data_val, size_t data_size)
{
#if PSI_DISABLE_SHUFFLE
    for (size_t i = 0; i < data_size; i++)
    {
        local_data.push_back(std::make_pair(data_key[i], data_val[i]));
    }
#else
    MelbourneShuffle shuffle(rand_ctx);
    local_data = shuffle.shuffle(data_key, data_val, data_size);
#endif
}

auto SelectHandler::get_result() -> v8
{
#ifdef PSI_SELECT_ONLY
    PRP prp;

    auto result = json::array();
    for (auto& [k, v] : local_data)
    {
        uint128_t key = prp(k);
        auto enc = homo.encrypt(v, *rand_ctx).to_vector();
        assert(!enc.empty());

        result.push_back(json::array({*reinterpret_cast<const PRP::binary*>(&key), enc}));
    }

    return json::to_msgpack(result);
#else
    abort();
#endif
}
