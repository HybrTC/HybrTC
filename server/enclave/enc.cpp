#include <cstddef>
#include <cstdint>
#include <memory>

#include <nlohmann/json.hpp>

#include "attestation.hpp"
#include "bloom_filter.hpp"
#include "common/types.hpp"
#include "common/uint128.hpp"
#include "crypto/ctr_drbg.hpp"
#include "crypto/gcm.hpp"
#include "cuckoo_hashing.hpp"
#include "log.h"
#include "paillier.hpp"
#include "prp.hpp"
#include "session.hpp"
#include "utils.hpp"

#include "helloworld_t.h"

using nlohmann::json;

std::vector<std::shared_ptr<VerifierContext>> verifiers;
std::map<uint32_t, std::shared_ptr<PSI::Session>> sessions;
std::shared_ptr<mbedtls::ctr_drbg> ctr_drbg;

static void init()
{
    if (ctr_drbg == nullptr)
    {
        ctr_drbg = std::make_shared<mbedtls::ctr_drbg>();
    }
}

/*
 * output:  vid, this_pk, format_setting
 */
void verifier_generate_challenge(uint8_t** obuf, size_t* olen)
{
    init();

    /* initialize verifier context */
    auto ctx = std::make_shared<VerifierContext>();

    /* set verifier id; generate and dump ephemeral public key */
    ctx->vid = verifiers.size();
    ctx->vpk = ctx->ecdh.make_public(*ctr_drbg);
    verifiers.push_back(ctx);

    /* generate output object */
    json json = json::object(
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
    const uint8_t* ibuf,
    size_t ilen,
    uint8_t** obuf,
    size_t* olen) -> uint32_t
{
    init();

    /* initialize attester context */
    AttesterContext ctx;

    /* set attester id; generate and dump ephemeral public key */
    mbedtls_ctr_drbg_random(ctr_drbg.get(), u8p(&ctx.aid), sizeof(ctx.aid));
    ctx.apk = ctx.ecdh.make_public(*ctr_drbg);

    /* deserialize and handle input */
    auto input = json::from_msgpack(ibuf, ibuf + ilen);
    ctx.vid = input["vid"].get<uint16_t>();        // set verifier id
    ctx.vpk = input["vpk"].get<v8>();              // set peer pk
    v8 format_settings = input["format_settings"]; // load format settings

    /* set vpk in ecdh context */
    ctx.ecdh.read_public(ctx.vpk);

    /* build claims and generate evidence*/
    auto evidence = ctx.core.get_evidence(format_settings, ctx.build_claims());

    /* generate output object */
    json json = json::object(
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
auto verifier_process_response(const uint8_t* ibuf, size_t ilen) -> uint32_t
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

constexpr uint32_t FILTER_POWER_BITS = 24;
constexpr uint32_t NUMBER_OF_HASHES = 4;

using HashSet = BloomFilter<FILTER_POWER_BITS, NUMBER_OF_HASHES>;
using HashTable = CuckooHashing<(1 << 16), (1 << 2), NUMBER_OF_HASHES>;

using KeyBin = a8<sizeof(uint128_t)>;

std::shared_ptr<PSI::Paillier> homo;

void set_paillier_public_key(uint32_t sid, const uint8_t* ibuf, size_t ilen)
{
    homo = std::make_shared<PSI::Paillier>();
    homo->load_pubkey(sessions[sid]->decrypt(ibuf, ilen));
}

void build_bloom_filter(
    uint32_t sid,
    const uint32_t* data_key,
    size_t data_size,
    uint8_t** obuf,
    size_t* olen)
{
    HashSet bloom_filter;
    PRP prp;

    for (size_t i = 0; i < data_size; i++)
    {
        bloom_filter.insert(prp(data_key[i]));
    }

    dump_enc(bloom_filter.data(), *sessions[sid], obuf, olen);
}

void match_bloom_filter(
    uint32_t sid,
    const uint32_t* data_key,
    const uint32_t* data_val,
    size_t data_size,
    const uint8_t* ibuf,
    size_t ilen,
    uint8_t** obuf,
    size_t* olen)
{
    HashSet bloom_filter(sessions[sid]->decrypt(ibuf, ilen));
    PRP prp;

    nlohmann::json hits = nlohmann::json::array();

    for (size_t i = 0; i < data_size; i++)
    {
        uint128_t key = prp(data_key[i]);
        if (bloom_filter.lookup(key))
        {
            auto enc = homo->encrypt(data_val[i], *ctr_drbg).to_vector();
            assert(!enc.empty());

            hits.push_back(nlohmann::json::array(
                {*reinterpret_cast<const KeyBin*>(&key), enc}));
        }
    }

    dump_enc(json::to_msgpack(hits), *sessions[sid], obuf, olen);
}

void aggregate(
    uint32_t peer_sid,
    uint32_t client_sid,
    const uint32_t* data_key,
    const uint32_t* data_val,
    size_t data_size,
    const uint8_t* ibuf,
    size_t ilen,
    uint8_t** obuf,
    size_t* olen)
{
    auto peer = json::from_msgpack(sessions[peer_sid]->decrypt(ibuf, ilen));

    /*
     * build cuckoo hashing table
     */
    PRP prp;
    HashTable hashing;

    for (size_t i = 0; i < data_size; i++)
    {
        hashing.insert(prp(data_key[i]), data_val[i]);
    }

    /*
     * aggregate calculation
     */
    json result = json::array();
    for (const auto& pair : peer)
    {
        KeyBin key_bin = pair[0];
        v8 val_bin = pair[1];

        const uint128_t& key =
            *reinterpret_cast<const uint128_t*>(key_bin.data());
        mbedtls::mpi peer_val(val_bin.data(), val_bin.size());

        auto query_result = hashing.lookup(key);

        for (auto val : query_result)
        {
            result.push_back(json::array(
                {pair[0],
                 homo->add(peer_val, homo->encrypt(val, *ctr_drbg))
                     .to_vector()}));
        }
    }

    dump_enc(json::to_msgpack(result), *sessions[client_sid], obuf, olen);
}
