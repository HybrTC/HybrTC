#pragma once

#include <array>

#include "common/bit_mask.hpp"
#include "hash.hpp"

/**
 * @brief Bloom Filter
 *
 * @tparam EE The length of the bloom filter (in bits) is 2**EE
 * @tparam HN The number of hashes
 * @tparam IT The type of input
 */
template <uint8_t EE, uint8_t HN, class IT = uint128_t>
class BloomFilter
{
    // bitmap for the filter
    using BT = uint64_t;
    constexpr static uint32_t BL = sizeof(BT) * 8;
    std::array<BT, ((1UL << EE) + BL - 1) / BL> bitmap = {0};

    // hash function
    using HT = uint32_t;
    HASH<HN, HT> hash;

    void bound_check(const HT& index) const
    {
        if (index >= (1UL << EE))
        {
            throw std::range_error(
                "the bit is beyond the range of this filter");
        }
    }

    void set_bit(const HT& index)
    {
        bound_check(index);
        uint32_t block_index = index / BL;
        uint32_t bit_index = index % BL;

        bitmap[block_index] |= BITMASK[bit_index];
    }

    void clear_bit(const HT& index)
    {
        bound_check(index);
        uint32_t block_index = index / BL;
        uint32_t bit_index = index % BL;

        return bitmap[block_index] &= ~BITMASK[bit_index];
    }

    bool test_bit(const HT& index) const
    {
        bound_check(index);
        uint32_t block_index = index / BL;
        uint32_t bit_index = index % BL;

        return bitmap[block_index] & BITMASK[bit_index];
    }

  public:
    void insert(IT key)
    {
        const std::array<HT, HN> hashes = hash(key);

        for (auto h : hashes)
        {
            set_bit(h % (1 << EE));
        }
    }

    bool lookup(IT key) const
    {
        const std::array<HT, HN> hashes = hash(key);

        for (auto h : hashes)
        {
            if (!test_bit(h % (1 << EE)))
            {
                return false;
            }
        }

        return true;
    }
};
