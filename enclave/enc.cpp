#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>

#include "bloom_filter.hpp"
#include "prp.hpp"

#include "helloworld_t.h"

constexpr uint32_t BLOOM_FILTER_BIT_POWER_LENGTH = 24;

BloomFilter<BLOOM_FILTER_BIT_POWER_LENGTH, 4> bloom_filter;

auto build_bloom_filter(const uint32_t* data, size_t length) -> size_t
{
    PRP prp;

    for (size_t i = 0; i < length; i++)
    {
        bloom_filter.insert(prp(data[i]));
    }

    return bloom_filter.size();
}

void get_bloom_filter(uint8_t* data, size_t length)
{
    if (bloom_filter.size() > length)
    {
        abort();
    }

    const auto* src =
        reinterpret_cast<const uint8_t*>(bloom_filter.serialize().data());

    memcpy(data, src, bloom_filter.size());
}