#pragma once

#include <vector>

#include "common/bit_mask.hpp"
#include "common/uint128.hpp"
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
    constexpr static size_t FILTER_BYTES = ((1UL << EE) + 7) / 8;
    using BITMAP = std::vector<uint8_t>;
    BITMAP bitmap;

    // hash function
    using HT = uint32_t;
    HASH<HN, HT, IT> hash;

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
        uint32_t block_index = index / 8;
        uint32_t bit_index = index % 8;

        bitmap[block_index] |= BITMASK[bit_index];
    }

    void clear_bit(const HT& index)
    {
        bound_check(index);
        uint32_t block_index = index / 8;
        uint32_t bit_index = index % 8;

        bitmap[block_index] &= ~BITMASK[bit_index];
    }

    [[nodiscard]] auto test_bit(const HT& index) const -> bool
    {
        bound_check(index);
        uint32_t block_index = index / 8;
        uint32_t bit_index = index % 8;

        return bool(bitmap[block_index] & BITMASK[bit_index]);
    }

  public:
    BloomFilter()
    {
        bitmap.resize(FILTER_BYTES, 0);
    }

    explicit BloomFilter(const BITMAP& bitmap) : bitmap(bitmap)
    {
        if (bitmap.size() < FILTER_BYTES)
        {
            abort();
        }
    }

    void insert(IT key)
    {
        const std::array<HT, HN> hashes = hash(key);

        for (auto h : hashes)
        {
            set_bit(h % (1 << EE));
        }
    }

    auto lookup(IT key) const -> bool
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

    [[nodiscard]] auto data() const -> const BITMAP&
    {
        return bitmap;
    }
};
