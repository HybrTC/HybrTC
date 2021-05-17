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
template <uint32_t LL, uint32_t LD, uint32_t HN, class KT = uint128_t, class VT = uint32_t>
class CuckooHashing
{
  protected:
    // element type
    using ET = std::pair<KT, VT>;

    // hash table
    constexpr static uint32_t D = 1 << LD;
    constexpr static uint32_t L = 1 << LL;
    using CHTABLE = std::array<std::array<std::vector<ET>, L>, HN>;
    std::unique_ptr<CHTABLE> table_ptr = std::make_unique<CHTABLE>();
    CHTABLE& table = *table_ptr;
    std::vector<ET> stash;

    // hash functions
    using HT = uint32_t;
    using HC = std::array<HT, HN>;
    HASH<HN, HT, KT> hash;

    void evict(uint32_t hash_index, uint32_t bin_index)
    {
        std::vector<ET>& bin = table[hash_index][bin_index];
        if (bin.size() != D)
        {
            printf(":( something bad happening: [%s][%d]\n", __PRETTY_FUNCTION__, __LINE__);
            abort();
        }

        for (auto it = bin.begin(); it < bin.end(); it++)
        {
            const HC hashes = hash(it->first);
            if (insert_from(it->first, it->second, hash_index + 1, hashes))
            {
                bin.erase(it);
                return;
            }
        }
    }

    auto insert_from(const KT& key, const VT& value, uint32_t hash_index, const HC& hashes) -> bool
    {
        if (hash_index >= HN)
        {
            return false;
        }

        for (uint32_t hi = hash_index; hi < HN; hi++)
        {
            uint32_t bi = hashes[hi] % L;
            std::vector<ET>& bin = table[hi][bi];

            if (bin.size() >= D)
            {
                evict(hi, bi);
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

    void insert(const KT& key, const VT& value)
    {
        const HC hashes = hash(key);
        if (!insert_from(key, value, 0, hashes))
        {
            stash.emplace_back(key, value);
        }
    }

    auto lookup(const KT& key) const -> std::vector<VT>
    {
        std::vector<VT> result;

        const std::array<HT, HN> hashes = hash(key);
        for (uint32_t hi = 0; hi < HN; hi++)
        {
            uint32_t bi = hashes[hi] % L;

            std::vector<ET>& bin = table[hi][bi];
            for (auto& e : bin)
            {
                if (e.first == key)
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
