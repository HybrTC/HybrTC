#pragma once

#include <vector>

#include "common/type_check.hpp"
#include "hash.hpp"

/**
 * @brief Bloom Filter
 *
 * @tparam LL The logarithm of the length of the bloom filter (in bits)
 * @tparam HN The number of hashes
 * @tparam IT The type of input
 */
template <uint8_t LL, uint8_t HN, class IT>
class BloomFilter
{
    INTEGER_CHECK(IT, "input value");

    constexpr static size_t BITS_PER_BYTE = 8;
    constexpr static std::array<uint8_t, BITS_PER_BYTE> BITMASK = {
        1UL << 0,
        1UL << 1,
        1UL << 2,
        1UL << 3,
        1UL << 4,
        1UL << 5,
        1UL << 6,
        1UL << 7};

    // bitmap for the filter
    constexpr static size_t FILTER_BYTES = ((1UL << LL) + 7) / BITS_PER_BYTE;
    using BITMAP = std::vector<uint8_t>;
    BITMAP bitmap;

    // hash function
    using HT = uint32_t;
    HASH<HN, HT, IT> hash;

    void bound_check(const HT& index) const
    {
        if (index >= (1UL << LL))
        {
            throw std::range_error(
                "the bit is beyond the range of this filter");
        }
    }

    template <bool set>
    void set_bit(const HT& index)
    {
        bound_check(index);
        uint32_t block_index = index / BITS_PER_BYTE;
        uint32_t bit_index = index % BITS_PER_BYTE;

        bitmap[block_index] = set ? bitmap[block_index] | BITMASK[bit_index]
                                  : bitmap[block_index] & ~BITMASK[bit_index];
    }

    [[nodiscard]] auto test_bit(const HT& index) const -> bool
    {
        bound_check(index);
        uint32_t block_index = index / BITS_PER_BYTE;
        uint32_t bit_index = index % BITS_PER_BYTE;

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
            set_bit<1>(h % (1 << LL));
        }
    }

    auto lookup(IT key) const -> bool
    {
        const std::array<HT, HN> hashes = hash(key);

        for (auto h : hashes)
        {
            if (!test_bit(h % (1 << LL)))
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
