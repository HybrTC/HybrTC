#pragma once

#include <string>

#include "common/type_check.hpp"
#include "hash.hpp"
#include "sgx/log.h"

/**
 * @brief Bloom Filter
 *
 * @tparam LL The logarithm of the length of the bloom filter (in bits)
 * @tparam HN The number of hashes
 * @tparam IT The type of input
 */
template <uint8_t HN, class ElemType>
class BloomFilter
{
    INTEGER_CHECK(ElemType, "input value");

    constexpr static size_t BITS_PER_BYTE = 8;
    constexpr static std::array<uint8_t, BITS_PER_BYTE> BITMASK =
        {1UL << 0, 1UL << 1, 1UL << 2, 1UL << 3, 1UL << 4, 1UL << 5, 1UL << 6, 1UL << 7};

    // bitmap for the filter
    size_t bitlen;
    std::string bitmap;

    // hash function
    using HT = uint32_t;
    HASH<HN, HT, ElemType> hash;

    template <bool set>
    void set_bit(const HT& index)
    {
        uint32_t block_index = index / BITS_PER_BYTE;
        uint32_t bit_index = index % BITS_PER_BYTE;

        bitmap[block_index] =
            set ? bitmap[block_index] | BITMASK[bit_index] : bitmap[block_index] & ~BITMASK[bit_index];
    }

    [[nodiscard]] auto test_bit(const HT& index) const -> bool
    {
        uint32_t block_index = index / BITS_PER_BYTE;
        uint32_t bit_index = index % BITS_PER_BYTE;

        return bool(bitmap[block_index] & BITMASK[bit_index]);
    }

  public:
    explicit BloomFilter(size_t bitlen) : bitlen(bitlen)
    {
        size_t bytelen = (bitlen + BITS_PER_BYTE - 1) / BITS_PER_BYTE;
        bitmap.resize(bytelen, 0);
    }

    explicit BloomFilter(size_t bitlen, std::string bitmap) : bitlen(bitlen), bitmap(std::move(bitmap))
    {
        size_t bytelen = (bitlen + BITS_PER_BYTE - 1) / BITS_PER_BYTE;
        if (bytelen > this->bitmap.size())
        {
            TRACE_ENCLAVE("the bitmap given is not long enough %lu < %lu", this->bitmap.size(), bytelen);
            abort();
        }
    }

    void insert(const ElemType& key)
    {
        const std::array<HT, HN> hashes = hash(key);

        for (auto h : hashes)
        {
            set_bit<1>(h % bitlen);
        }
    }

    auto lookup(const ElemType& key) const -> bool
    {
        const std::array<HT, HN> hashes = hash(key);

        for (auto h : hashes)
        {
            if (!test_bit(h % bitlen))
            {
                return false;
            }
        }

        return true;
    }

    [[nodiscard]] auto data() const -> const std::string&
    {
        return bitmap;
    }
};
