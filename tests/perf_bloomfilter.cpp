#include <cstdio>
#include <fstream>
#include <iostream>
#include <iterator>
#include <map>
#include <utility>

#include <nlohmann/json.hpp>

#include "enclave/psi/bloom_filter.hpp"
#include "enclave/psi/prp.hpp"
#include "host/spdlog.hpp"
#include "host/timer.hpp"
#include "prng.hpp"
#include "spdlog/spdlog.h"

using nlohmann::json;

constexpr static u32 NUMBER_OF_HASHES = 4;
constexpr static u32 FILTER_POWER_BITS = 24;

using HashSet = BloomFilter<NUMBER_OF_HASHES, PRP::integer>;

auto test(unsigned log_count)
{
    Timer timer;

    // prepare data set
    const size_t count = 1 << log_count;
    PRNG<PRP::integer> prng;
    std::vector<PRP::integer> keys;
    keys.reserve(count);
    while (keys.size() < count)
    {
        keys.emplace_back(prng());
    }

    HashSet filter(1 << FILTER_POWER_BITS);
    timer("build:start");
    for (const auto& key : keys)
    {
        filter.insert(key);
    }
    timer("build:done");

    timer("match:start");
    for (const auto& key : keys)
    {
        (void)filter.lookup(key);
    }
    timer("match:done");

    return json::object({{"log_count", log_count}, {"timer", timer.to_json()}});
}

auto main() -> int
{
    auto result = json::array();

    for (size_t i = 0; i < 16; i++)
    {
        for (size_t l = 10; l <= 20; l += 2)
        {
            SPDLOG_INFO("{}/16 log = {}", i, l);
            result.emplace_back(test(l));
        }
    }

    std::ofstream of("perf_bloomfilter.json");
    of << result.dump() << std::endl;
    of.close();
}
