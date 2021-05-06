

#include "../common/bloom_filter.hpp"

constexpr uint32_t FILTER_POWER_BITS = 24;
constexpr uint32_t NUMBER_OF_HASHES = 4;

using HashSet = BloomFilter<FILTER_POWER_BITS, NUMBER_OF_HASHES>;

int main()
{
    HashSet bloom_filter;
    bloom_filter.insert(1);
}