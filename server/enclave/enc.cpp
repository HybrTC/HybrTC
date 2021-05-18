#include <cstring>
#include <nlohmann/json.hpp>

#include "common/types.hpp"
#include "common/uint128.hpp"
#include "config.hpp"
#include "crypto/ctr_drbg.hpp"
#include "enclave_context.hpp"
#include "paillier.hpp"
#include "psi/bloom_filter.hpp"
#include "psi/cuckoo_hashing.hpp"
#include "psi/melbourne.hpp"
#include "psi/prp.hpp"
#include "sgx/attestation.hpp"
#include "sgx/log.h"

#include "helloworld_t.h"

using mbedtls::mpi;
using nlohmann::json;

sptr<EnclaveContext> global;

static void init()
{
    if (global == nullptr)
    {
        global = std::make_shared<EnclaveContext>();
    }
}

void verifier_generate_challenge(u8** obuf, size_t* olen)
{
    init();
    global->verifier_generate_challenge(obuf, olen);
}

auto attester_generate_response(const u8* ibuf, size_t ilen, u8** obuf, size_t* olen) -> u32
{
    init();
    return global->attester_generate_response(ibuf, ilen, obuf, olen);
}

auto verifier_process_response(const u8* ibuf, size_t ilen) -> u32
{
    return global->verifier_process_response(ibuf, ilen);
}

constexpr u32 FILTER_POWER_BITS = 24;
constexpr u32 NUMBER_OF_HASHES = 4;
constexpr u32 CH_LOG_LENGTH = 16;
constexpr u32 CH_LOG_DEPTH = 2;

using HashSet = BloomFilter<FILTER_POWER_BITS, NUMBER_OF_HASHES, PRP::integer>;
using HashTable = CuckooHashing<CH_LOG_LENGTH, CH_LOG_DEPTH, NUMBER_OF_HASHES>;

sptr<PSI::Paillier> homo;

bool half_data = false;
database_t local_data;
database_t left_data;

void set_client_query(
    u32 sid,
    const u8* ibuf,
    size_t ilen,
    bool half,
    const u32* data_key,
    const u32* data_val,
    size_t data_size)
{
    homo = std::make_shared<PSI::Paillier>();
    homo->load_pubkey(global->session(sid).decrypt(ibuf, ilen));

    half_data = half;

#if PSI_DISABLE_SHUFFLE
    for (size_t i = 0; i < data_size; i++)
    {
        local_data.push_back(std::make_pair(data_key[i], data_val[i]));
    }
#else
    MelbourneShuffle shuffle(global->rand_ptr());
    local_data = shuffle.shuffle(data_key, data_val, data_size);
#endif

#ifndef PSI_SELECT_ONLY
    if (half)
    {
        size_t mid = local_data.size() / 2;

        left_data.resize(local_data.size() - mid);
        memcpy(u8p(&left_data[0]), u8p(&local_data[mid]), left_data.size() * sizeof(left_data[0]));

        local_data.resize(mid);
    }
#endif
}

void get_select_result(u32 sid, u8** obuf, size_t* olen)
{
#ifdef PSI_SELECT_ONLY
    PRP prp;

    auto result = json::array();
    for (auto& [k, v] : local_data)
    {
        uint128_t key = prp(k);
        auto enc = homo->encrypt(v, global->rand()).to_vector();
        assert(!enc.empty());

        result.push_back(json::array({*reinterpret_cast<const PRP::binary*>(&key), enc}));
    }

    global->dump_enc(sid, json::to_msgpack(result), obuf, olen);
#else
    (void)(sid);
    (void)(obuf);
    (void)(olen);

    abort();
#endif
}

void build_bloom_filter(u32 sid, u8** obuf, size_t* olen)
{
    HashSet bloom_filter;
    PRP prp;

    for (auto& [k, _] : local_data)
    {
        bloom_filter.insert(prp(k));
    }

    global->dump_enc(sid, bloom_filter.data(), obuf, olen);
}

void match_bloom_filter(u32 sid, const u8* ibuf, size_t ilen, u8** obuf, size_t* olen)
{
    HashSet bloom_filter(global->session(sid).decrypt(ibuf, ilen));
    PRP prp;

    auto hits = json::array();

    if (half_data)
    {
        for (auto& [k, v] : left_data)
        {
            uint128_t key = prp(k);
            if (bloom_filter.lookup(key))
            {
                auto enc = homo->encrypt(v, global->rand()).to_vector();
                assert(!enc.empty());

                hits.push_back(json::array({*reinterpret_cast<const PRP::binary*>(&key), enc}));
            }
        }
    }
    else
    {
        for (auto& [k, v] : local_data)
        {
            uint128_t key = prp(k);
            if (bloom_filter.lookup(key))
            {
                auto enc = homo->encrypt(v, global->rand()).to_vector();
                assert(!enc.empty());

                hits.push_back(json::array({*reinterpret_cast<const PRP::binary*>(&key), enc}));
            }
        }
    }

    global->dump_enc(sid, json::to_msgpack(hits), obuf, olen);
}

void aggregate(u32 peer_sid, u32 client_sid, const u8* ibuf, size_t ilen, u8** obuf, size_t* olen)
{
    auto peer = json::from_msgpack(global->session(peer_sid).decrypt(ibuf, ilen));

    /*
     * build cuckoo hashing table
     */
    PRP prp;
    HashTable hashing;

    for (auto& [k, v] : local_data)
    {
        hashing.insert(prp(k), v);
    }

    /*
     * aggregate calculation
     */

    auto result = json::array();
    for (const auto& pair : peer)
    {
        PRP::binary key_bin = pair[0];
        v8 val_bin = pair[1];

        const uint128_t& key = *reinterpret_cast<const uint128_t*>(key_bin.data());
        mpi peer_val(val_bin.data(), val_bin.size());

        auto query_result = hashing.lookup(key);

        for (auto val : query_result)
        {
#ifdef PSI_JOIN_COUNT
            result.push_back(val);
#else
            result.push_back(
                json::array({pair[0], homo->add(peer_val, homo->encrypt(val, global->rand())).to_vector()}));
#endif
        }
    }

#ifdef PSI_JOIN_COUNT
    auto ret = json::array({result.size(), global->rand().rand<size_t>()});
    global->dump_enc(client_sid, json::to_msgpack(ret), obuf, olen);
#else
    global->dump_enc(client_sid, json::to_msgpack(result), obuf, olen);
#endif
}
