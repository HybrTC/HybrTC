#pragma once

#include <array>
#include <cstdint>
#include <memory>
#include <vector>

#include "common/uint128.hpp"
#include "hash.hpp"

/**
 * @brief   the table can accomodate L*D*HN elements
 *
 * @tparam LL    logarithm of the length of a single table
 * @tparam LD    logarithm of the number of elements in a single bin
 * @tparam HN   number of hash functions
 * @tparam KT   key type
 * @tparam VT   value type
 */
template <uint32_t LL, uint32_t LD, uint32_t HashNum, class KeyType = uint128_t, class ValType = uint32_t>
class CuckooHashing
{
  protected:
    // element type
    using ElemType = std::pair<KeyType, ValType>;

    // hash table
    constexpr static uint32_t D = 1 << LD;
    constexpr static uint32_t L = 1 << LL;
    using CHTable = std::array<std::array<std::vector<ElemType>, L>, HashNum>;
    std::unique_ptr<CHTable> table_ptr = std::make_unique<CHTable>();
    CHTable& table = *table_ptr;
    std::vector<ElemType> stash;

    // hash functions
    using HashType = uint32_t;
    HASH<HashNum, HashType, KeyType> hash;

    void evict(uint32_t hash_index, uint32_t bin_index)
    {
        std::vector<ElemType>& bin = table[hash_index][bin_index];
        if (bin.size() != D)
        {
            printf(":( something bad happening: [%s][%d]\n", __PRETTY_FUNCTION__, __LINE__);
            abort();
        }

        for (auto it = bin.begin(); it < bin.end(); it++)
        {
            auto hashes = hash(it->first);
            if (insert_from(it->first, it->second, hash_index + 1, hashes))
            {
                bin.erase(it);
                return;
            }
        }
    }

    auto insert_from(
        const KeyType& key,
        const ValType& value,
        uint32_t hash_index,
        const std::array<HashType, HashNum>& hashes) -> bool
    {
        if (hash_index >= HashNum)
        {
            return false;
        }

        // see if there's a seat
        for (uint32_t hi = hash_index; hi < HashNum; hi++)
        {
            std::vector<ElemType>& bin = table[hi][hashes[hi] % L];

            if (bin.size() < D)
            {
                bin.emplace_back(key, value);
                return true;
            }
        }

        for (uint32_t hi = hash_index; hi < HashNum; hi++)
        {
            uint32_t bi = hashes[hi] % L;
            std::vector<ElemType>& bin = table[hi][bi];

            if (bin.size() >= D)
            {
                evict(hi, bi); // this may modify the size of bin
            }

            if (bin.size() < D)
            {
                bin.emplace_back(key, value);
                return true;
            }
        }

        return false;
    }

  public:
    CuckooHashing() = default;

    // forbid copy constructor
    CuckooHashing(const CuckooHashing& other) = delete;

    void insert(const KeyType& key, const ValType& value)
    {
        const auto hashes = hash(key);
        if (!insert_from(key, value, 0, hashes))
        {
            stash.emplace_back(key, value);
        }
    }

    auto lookup(const KeyType& key) const -> std::vector<ValType>
    {
        std::vector<ValType> result;

        const std::array<HashType, HashNum> hashes = hash(key);
        for (uint32_t hi = 0; hi < HashNum; hi++)
        {
            uint32_t bi = hashes[hi] % L;

            const std::vector<ElemType>& bin = table[hi][bi];
            for (const auto& e : bin)
            {
                if (memcmp(&e.first, &key, sizeof(uint128_t)) == 0)
                {
                    result.push_back(e.second);
                }
            }
        }

        for (auto& e : stash)
        {
            if (e.first == key)
            {
                result.push_back(e.second);
            }
        }

        return result;
    }
};
