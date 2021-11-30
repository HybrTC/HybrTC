#include <cstdio>
#include <fstream>
#include <iostream>
#include <iterator>
#include <map>
#include <utility>

#include <nlohmann/json.hpp>

#include "enclave/psi/cuckoo_hashing.hpp"
#include "enclave/psi/prp.hpp"
#include "host/spdlog.hpp"
#include "host/timer.hpp"
#include "prng.hpp"
#include "spdlog/spdlog.h"

using nlohmann::json;

constexpr static u32 CH_LOG_LENGTH = 17;
constexpr static u32 CH_LOG_DEPTH = 2;
constexpr static u32 NUMBER_OF_HASHES = 4;
using HashTable = CuckooHashing<NUMBER_OF_HASHES>;

auto test(unsigned log_count)
{
    Timer timer;

    // prepare data set
    const size_t count = 1 << log_count;
    PRNG<PRP::integer> kPrng;
    PRNG<u32> vPrng;
    std::vector<std::pair<PRP::integer, u32>> data;
    data.reserve(count);
    while (data.size() < count)
    {
        data.emplace_back(kPrng(), vPrng());
    }

    HashTable hashing(1 << CH_LOG_LENGTH, 1 << CH_LOG_DEPTH);
    timer("build:start");
    for (const auto& [key, val] : data)
    {
        hashing.insert(key, val);
    }
    timer("build:done");

    timer("match:start");
    for (const auto& [key, _] : data)
    {
        (void)hashing.lookup(key);
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

    std::ofstream of("perf_cuckoohashing.json");
    of << result.dump() << std::endl;
    of.close();
}
