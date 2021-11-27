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
 * @tparam HashNum   number of hash functions
 * @tparam KeyType   key type
 * @tparam ValType   value type
 */
template <uint32_t HashNum, class KeyType = uint128_t, class ValType = uint32_t>
class CuckooHashing
{
  protected:
    // element type
    using ElemType = std::pair<KeyType, ValType>;

    // hash table
    uint32_t table_length;
    uint32_t table_depth;

    using CHTable = std::array<std::vector<std::vector<ElemType>>, HashNum>;
    std::unique_ptr<CHTable> table_ptr = std::make_unique<CHTable>();
    CHTable& table = *table_ptr;
    std::vector<ElemType> stash;

    // hash functions
    using HashType = uint32_t;
    HASH<HashNum, HashType, KeyType> hash;

    void evict(uint32_t hash_index, uint32_t bin_index)
    {
        std::vector<ElemType>& bin = table[hash_index][bin_index];
        if (bin.size() != table_depth)
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
            std::vector<ElemType>& bin = table[hi][hashes[hi] % table_length];

            if (bin.size() < table_depth)
            {
                bin.emplace_back(key, value);
                return true;
            }
        }

        for (uint32_t hi = hash_index; hi < HashNum; hi++)
        {
            uint32_t bi = hashes[hi] % table_length;
            std::vector<ElemType>& bin = table[hi][bi];

            if (bin.size() >= table_depth)
            {
                evict(hi, bi); // this may modify the size of bin
            }

            if (bin.size() < table_depth)
            {
                bin.emplace_back(key, value);
                return true;
            }
        }

        return false;
    }

  public:
    CuckooHashing(uint32_t length, uint32_t depth) : table_length(length), table_depth(depth)
    {
        for (auto& vec : table)
        {
            vec.resize(length);
        }
    }

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
            uint32_t bi = hashes[hi] % table_length;

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
