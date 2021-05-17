#include <cstdio>
#include <iostream>
#include <map>
#include <utility>

#include <nlohmann/json.hpp>

#include "../server/enclave/psi/cuckoo_hashing.hpp"
#include "../server/enclave/psi/prp.hpp"
#include "prng.hpp"
#include "utils/spdlog.hpp"

using nlohmann::json;

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
class CHTest : public CuckooHashing<LL, LD, HN, KT, VT>
{
  public:
    auto run() -> std::map<size_t, size_t>
    {
        PRNG<KT> Kprng;
        PRNG<VT> Vprng;

        std::map<size_t, size_t> result;
        size_t i = 0;

#define TEST_SUITE(limit)                     \
    do                                        \
    {                                         \
        for (; i < (1 << (limit)); i++)       \
        {                                     \
            this->insert(Kprng(), Vprng());   \
        }                                     \
        fprintf(stderr, "%d ", limit);        \
        result[(limit)] = this->stash.size(); \
    } while (0);

        TEST_SUITE(10);

        TEST_SUITE(12);

        if (LL + LD > 14)
        {
            TEST_SUITE(14);
        }

        if (LL + LD > 16)
        {
            TEST_SUITE(16);
        }

        if (LL + LD > 18)
        {
            TEST_SUITE(18);
        }

        if (LL + LD > 20)
        {
            TEST_SUITE(20);
        }

        fputs("\n", stderr);

        return result;
    }

    void inspect() const
    {
        for (uint32_t hi = 0; hi < HN; hi++)
        {
            printf("| ");
            for (uint32_t bi = 0; bi < this->L; bi++)
            {
                auto& bin = this->table[hi][bi];
                if (bin.size() > 0)
                {
                    printf("%lu ", bin.size());
                }
                else
                {
                    printf("- ");
                }
            }
            printf("| ");
        }
        printf("| stash = %lu |\n", this->stash.size());
    }
};

void dump_json(const std::string& fn, const json& obj)
{
    FILE* fp = std::fopen(fn.c_str(), "w");
    fputs(obj.dump().c_str(), fp);
    fclose(fp);
}

template <u32 CH_LOG_LENGTH, u32 CH_LOG_DEPTH, u32 NUMBER_OF_HASHES>
auto test(size_t repeat) -> json
{
    json ret = json::array();

    for (size_t i = 0; i < repeat; i++)
    {
        CHTest<CH_LOG_LENGTH, CH_LOG_DEPTH, NUMBER_OF_HASHES> test;
        auto stah_size = test.run();
        ret.push_back(stah_size);
    }

    auto x = json::object(
        {{"log_table_length", CH_LOG_LENGTH},
         {"log_bin_depth", CH_LOG_DEPTH},
         {"hashes", NUMBER_OF_HASHES},
         {"stash_sizes", ret}});

    auto fn = fmt::format(
        "{:%Y%m%dT%H%M%S}-{}-{}-{}.json", fmt::localtime(time(nullptr)), CH_LOG_LENGTH, CH_LOG_DEPTH, NUMBER_OF_HASHES);

    dump_json(fn, x);

    return x;
}

auto main() -> int
{
    puts("start");

    // constexpr u32 CH_LOG_LENGTH = 18;
    // constexpr u32 CH_LOG_DEPTH = 2;
    // constexpr u32 NUMBER_OF_HASHES = 4;

    constexpr u32 TEST_COUNT = 10;

    json result = json::array();

#ifndef PSI_CH_LOG_LENGTH
#define PSI_CH_LOG_LENGTH 8
#endif

    SPDLOG_INFO("{}", "test<PSI_CH_LOG_LENGTH, 3, 2>(TEST_COUNT)");
    result.push_back(test<PSI_CH_LOG_LENGTH, 3, 2>(TEST_COUNT));
    SPDLOG_INFO("{}", "test<PSI_CH_LOG_LENGTH, 3, 3>(TEST_COUNT)");
    result.push_back(test<PSI_CH_LOG_LENGTH, 3, 3>(TEST_COUNT));
    SPDLOG_INFO("{}", "test<PSI_CH_LOG_LENGTH, 3, 4>(TEST_COUNT)");
    result.push_back(test<PSI_CH_LOG_LENGTH, 3, 4>(TEST_COUNT));
    SPDLOG_INFO("{}", "test<PSI_CH_LOG_LENGTH, 3, 5>(TEST_COUNT)");
    result.push_back(test<PSI_CH_LOG_LENGTH, 3, 5>(TEST_COUNT));
    SPDLOG_INFO("{}", "test<PSI_CH_LOG_LENGTH, 3, 6>(TEST_COUNT)");
    result.push_back(test<PSI_CH_LOG_LENGTH, 3, 6>(TEST_COUNT));
    SPDLOG_INFO("{}", "test<PSI_CH_LOG_LENGTH, 3, 7>(TEST_COUNT)");
    result.push_back(test<PSI_CH_LOG_LENGTH, 3, 7>(TEST_COUNT));
    SPDLOG_INFO("{}", "test<PSI_CH_LOG_LENGTH, 3, 8>(TEST_COUNT)");
    result.push_back(test<PSI_CH_LOG_LENGTH, 3, 8>(TEST_COUNT));

    SPDLOG_INFO("{}", "test<PSI_CH_LOG_LENGTH, 2, 2>(TEST_COUNT)");
    result.push_back(test<PSI_CH_LOG_LENGTH, 2, 2>(TEST_COUNT));
    SPDLOG_INFO("{}", "test<PSI_CH_LOG_LENGTH, 2, 3>(TEST_COUNT)");
    result.push_back(test<PSI_CH_LOG_LENGTH, 2, 3>(TEST_COUNT));
    SPDLOG_INFO("{}", "test<PSI_CH_LOG_LENGTH, 2, 4>(TEST_COUNT)");
    result.push_back(test<PSI_CH_LOG_LENGTH, 2, 4>(TEST_COUNT));
    SPDLOG_INFO("{}", "test<PSI_CH_LOG_LENGTH, 2, 5>(TEST_COUNT)");
    result.push_back(test<PSI_CH_LOG_LENGTH, 2, 5>(TEST_COUNT));
    SPDLOG_INFO("{}", "test<PSI_CH_LOG_LENGTH, 2, 6>(TEST_COUNT)");
    result.push_back(test<PSI_CH_LOG_LENGTH, 2, 6>(TEST_COUNT));
    SPDLOG_INFO("{}", "test<PSI_CH_LOG_LENGTH, 2, 7>(TEST_COUNT)");
    result.push_back(test<PSI_CH_LOG_LENGTH, 2, 7>(TEST_COUNT));
    SPDLOG_INFO("{}", "test<PSI_CH_LOG_LENGTH, 2, 8>(TEST_COUNT)");
    result.push_back(test<PSI_CH_LOG_LENGTH, 2, 8>(TEST_COUNT));

    SPDLOG_INFO("{}", "test<PSI_CH_LOG_LENGTH, 1, 2>(TEST_COUNT)");
    result.push_back(test<PSI_CH_LOG_LENGTH, 1, 2>(TEST_COUNT));
    SPDLOG_INFO("{}", "test<PSI_CH_LOG_LENGTH, 1, 3>(TEST_COUNT)");
    result.push_back(test<PSI_CH_LOG_LENGTH, 1, 3>(TEST_COUNT));
    SPDLOG_INFO("{}", "test<PSI_CH_LOG_LENGTH, 1, 4>(TEST_COUNT)");
    result.push_back(test<PSI_CH_LOG_LENGTH, 1, 4>(TEST_COUNT));
    SPDLOG_INFO("{}", "test<PSI_CH_LOG_LENGTH, 1, 5>(TEST_COUNT)");
    result.push_back(test<PSI_CH_LOG_LENGTH, 1, 5>(TEST_COUNT));
    SPDLOG_INFO("{}", "test<PSI_CH_LOG_LENGTH, 1, 6>(TEST_COUNT)");
    result.push_back(test<PSI_CH_LOG_LENGTH, 1, 6>(TEST_COUNT));
    SPDLOG_INFO("{}", "test<PSI_CH_LOG_LENGTH, 1, 7>(TEST_COUNT)");
    result.push_back(test<PSI_CH_LOG_LENGTH, 1, 7>(TEST_COUNT));
    SPDLOG_INFO("{}", "test<PSI_CH_LOG_LENGTH, 1, 8>(TEST_COUNT)");
    result.push_back(test<PSI_CH_LOG_LENGTH, 1, 8>(TEST_COUNT));

    SPDLOG_INFO("{}", "test<PSI_CH_LOG_LENGTH, 0, 2>(TEST_COUNT)");
    result.push_back(test<PSI_CH_LOG_LENGTH, 0, 2>(TEST_COUNT));
    SPDLOG_INFO("{}", "test<PSI_CH_LOG_LENGTH, 0, 3>(TEST_COUNT)");
    result.push_back(test<PSI_CH_LOG_LENGTH, 0, 3>(TEST_COUNT));
    SPDLOG_INFO("{}", "test<PSI_CH_LOG_LENGTH, 0, 4>(TEST_COUNT)");
    result.push_back(test<PSI_CH_LOG_LENGTH, 0, 4>(TEST_COUNT));
    SPDLOG_INFO("{}", "test<PSI_CH_LOG_LENGTH, 0, 5>(TEST_COUNT)");
    result.push_back(test<PSI_CH_LOG_LENGTH, 0, 5>(TEST_COUNT));
    SPDLOG_INFO("{}", "test<PSI_CH_LOG_LENGTH, 0, 6>(TEST_COUNT)");
    result.push_back(test<PSI_CH_LOG_LENGTH, 0, 6>(TEST_COUNT));
    SPDLOG_INFO("{}", "test<PSI_CH_LOG_LENGTH, 0, 7>(TEST_COUNT)");
    result.push_back(test<PSI_CH_LOG_LENGTH, 0, 7>(TEST_COUNT));
    SPDLOG_INFO("{}", "test<PSI_CH_LOG_LENGTH, 0, 8>(TEST_COUNT)");
    result.push_back(test<PSI_CH_LOG_LENGTH, 0, 8>(TEST_COUNT));

    puts("end");
}
