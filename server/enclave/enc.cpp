#include <cstring>
#include <nlohmann/json.hpp>

#include "common/types.hpp"
#include "common/uint128.hpp"
#include "config.hpp"
#include "crypto/ctr_drbg.hpp"
#include "crypto/gcm.hpp"
#include "paillier.hpp"
#include "psi/bloom_filter.hpp"
#include "psi/cuckoo_hashing.hpp"
#include "psi/melbourne.hpp"
#include "psi/prp.hpp"
#include "sgx/attestation.hpp"

#include "helloworld_t.h"

using mbedtls::mpi;
using nlohmann::json;

std::vector<sptr<VerifierContext>> verifiers;
std::map<u32, sptr<PSI::Session>> sessions;
sptr<mbedtls::ctr_drbg> rand_ctx;

static void init()
{
    if (rand_ctx == nullptr)
    {
        rand_ctx = std::make_shared<mbedtls::ctr_drbg>();
    }
}

static void dump(const v8& bytes, uint8_t** obuf, size_t* olen)
{
    *olen = bytes.size();
    *obuf = u8p(oe_host_malloc(bytes.size()));
    memcpy(*obuf, bytes.data(), bytes.size());
}

static void dump_enc(
    const v8& bytes,
    PSI::Session& aes,
    uint8_t** obuf,
    size_t* olen)
{
    dump(aes.encrypt(bytes), obuf, olen);
}

/*
 * output:  vid, this_pk, format_setting
 */
void verifier_generate_challenge(u8** obuf, size_t* olen)
{
    init();

    /* initialize verifier context */
    auto ctx = std::make_shared<VerifierContext>();

    /* set verifier id; generate and dump ephemeral public key */
    ctx->vid = verifiers.size();
    ctx->vpk = ctx->ecdh.make_public(*rand_ctx);
    verifiers.push_back(ctx);

    /* generate output object */
    auto json = json::object(
        {{"vid", ctx->vid},
         {"vpk", ctx->vpk},
         {"format_settings", ctx->core.format_settings()}});

    dump(json::to_msgpack(json), obuf, olen);
}

/*
 * input:   vid, peer_pk, format_settings
 * output:  vid, aid, this_pk, evidence
 */
auto attester_generate_response(
    const u8* ibuf,
    size_t ilen,
    u8** obuf,
    size_t* olen) -> u32
{
    init();

    /* initialize attester context */
    AttesterContext ctx;

    /* set attester id; generate and dump ephemeral public key */
    mbedtls_ctr_drbg_random(rand_ctx.get(), u8p(&ctx.aid), sizeof(ctx.aid));
    ctx.apk = ctx.ecdh.make_public(*rand_ctx);

    /* deserialize and handle input */
    auto input = json::from_msgpack(ibuf, ibuf + ilen);
    ctx.vid = input["vid"].get<uint16_t>();       // set verifier id
    ctx.vpk = input["vpk"].get<v8>();             // set peer pk
    auto fs = input["format_settings"].get<v8>(); // load format settings

    /* set vpk in ecdh context */
    ctx.ecdh.read_public(ctx.vpk);

    /* build claims and generate evidence*/
    auto evidence = ctx.core.get_evidence(fs, ctx.build_claims());

    /* generate output object */
    auto json = json::object(
        {{"vid", ctx.vid},
         {"aid", ctx.aid},
         {"apk", ctx.apk},
         {"evidence", evidence}});

    dump(json::to_msgpack(json), obuf, olen);

    /* build crypto context */
    return ctx.complete_attestation();
}

/*
 * input:   vid, aid, evidence
 * output:  attestation_result
 */
auto verifier_process_response(const u8* ibuf, size_t ilen) -> u32
{
    /* deserialize and handle input */
    auto input = json::from_msgpack(ibuf, ibuf + ilen);

    auto ctx = verifiers[input["vid"].get<uint16_t>()]; // load verifier context
    ctx->aid = input["aid"].get<uint16_t>();            // set attester id
    ctx->apk = input["apk"].get<v8>();                  // set attester pubkey
    auto evidence = input["evidence"].get<v8>(); // load attestation evidence

    /* set vpk in ecdh context */
    ctx->ecdh.read_public(ctx->apk);

    /* verify evidence */
    auto claims = ctx->core.verify_evidence(evidence).custom_claims_buffer();

    /* compare claims: (1) size (2) compare content in constant time */
    auto claims_ = ctx->build_claims();
    if (claims_.size() != claims.value_size)
    {
        return -1;
    }

    unsigned result = 0;
    for (size_t i = 0; i < claims_.size() && i < claims.value_size; i++)
    {
        result += (claims_[i] ^ claims.value[i]);
    }
    if (result != 0)
    {
        return -1;
    }

    /* build crypto context and free verifier context */
    auto sid = ctx->complete_attestation();
    verifiers[ctx->vid] = nullptr;

    return sid;
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
    homo->load_pubkey(sessions[sid]->decrypt(ibuf, ilen));

    half_data = half;
    local_data = melbourne_shuffle(data_key, data_val, data_size);

#ifndef PSI_SELECT_ONLY
    if (half)
    {
        size_t mid = local_data.size() / 2;

        left_data.resize(local_data.size() - mid);
        memcpy(
            u8p(&left_data[0]),
            u8p(&local_data[mid]),
            left_data.size() * sizeof(left_data[0]));

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
        auto enc = homo->encrypt(v, *rand_ctx).to_vector();
        assert(!enc.empty());

        result.push_back(
            json::array({*reinterpret_cast<const PRP::binary*>(&key), enc}));
    }

    dump_enc(json::to_msgpack(result), *sessions[sid], obuf, olen);
#else
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

    dump_enc(bloom_filter.data(), *sessions[sid], obuf, olen);
}

void match_bloom_filter(
    u32 sid,
    const u8* ibuf,
    size_t ilen,
    u8** obuf,
    size_t* olen)
{
    HashSet bloom_filter(sessions[sid]->decrypt(ibuf, ilen));
    PRP prp;

    auto hits = json::array();

    if (half_data)
    {
        for (auto& [k, v] : left_data)
        {
            uint128_t key = prp(k);
            if (bloom_filter.lookup(key))
            {
                auto enc = homo->encrypt(v, *rand_ctx).to_vector();
                assert(!enc.empty());

                hits.push_back(json::array(
                    {*reinterpret_cast<const PRP::binary*>(&key), enc}));
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
                auto enc = homo->encrypt(v, *rand_ctx).to_vector();
                assert(!enc.empty());

                hits.push_back(json::array(
                    {*reinterpret_cast<const PRP::binary*>(&key), enc}));
            }
        }
    }

    dump_enc(json::to_msgpack(hits), *sessions[sid], obuf, olen);
}

void aggregate(
    u32 peer_sid,
    u32 client_sid,
    const u8* ibuf,
    size_t ilen,
    u8** obuf,
    size_t* olen)
{
    auto peer = json::from_msgpack(sessions[peer_sid]->decrypt(ibuf, ilen));

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

        const uint128_t& key =
            *reinterpret_cast<const uint128_t*>(key_bin.data());
        mpi peer_val(val_bin.data(), val_bin.size());

        auto query_result = hashing.lookup(key);

        for (auto val : query_result)
        {
            result.push_back(json::array(
                {pair[0],
                 homo->add(peer_val, homo->encrypt(val, *rand_ctx))
                     .to_vector()}));
        }
    }

    dump_enc(json::to_msgpack(result), *sessions[client_sid], obuf, olen);
}
