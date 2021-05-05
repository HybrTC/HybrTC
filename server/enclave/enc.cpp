#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <memory>
#include <vector>

#include <mbedtls/sha256.h>
#include <nlohmann/json.hpp>

#include "attestation/attester.hpp"
#include "attestation/verifier.hpp"
#include "bloom_filter.hpp"
#include "common/types.hpp"
#include "common/uint128.hpp"
#include "crypto/ctr_drbg.hpp"
#include "crypto/ecdh.hpp"
#include "crypto/gcm.hpp"
#include "cuckoo_hashing.hpp"
#include "log.h"
#include "paillier.hpp"
#include "prp.hpp"

#include "helloworld_t.h"

constexpr uint32_t FILTER_POWER_BITS = 24;
constexpr uint32_t NUMBER_OF_HASHES = 4;

using HashSet = BloomFilter<FILTER_POWER_BITS, NUMBER_OF_HASHES>;
using HashTable = CuckooHashing<(1 << 16), (1 << 2), NUMBER_OF_HASHES>;

using KeyBin = a8<sizeof(uint128_t)>;

struct AttestationContext
{
    constexpr static oe_uuid_t format_id{OE_FORMAT_UUID_SGX_LOCAL_ATTESTATION};

    std::shared_ptr<Attester> attester = std::make_shared<Attester>(&format_id);
    std::shared_ptr<Verifier> verifier = std::make_shared<Verifier>(&format_id);

    std::shared_ptr<mbedtls::ctr_drbg> rand_ctx =
        std::make_shared<mbedtls::ctr_drbg>();
    std::shared_ptr<mbedtls::ecdh> ecdh_ctx =
        std::make_shared<mbedtls::ecdh>(mbedtls::MBEDTLS_ECP_DP_SECP256R1);

    v8 this_pk;
    v8 peer_pk;
};

std::shared_ptr<mbedtls::ctr_drbg> ctr_drbg;

std::shared_ptr<AttestationContext> ctx;
using aes_gcm_256 =
    mbedtls::gcm<mbedtls::MBEDTLS_CIPHER_ID_AES, mbedtls::aes::KEY_LEN_256>;
std::shared_ptr<aes_gcm_256> crypto_ctx;

void initialize_attestation(
    uint8_t** pk,
    size_t* pk_len,
    uint8_t** format_setting,
    size_t* format_setting_len)
{
    if (ctx == nullptr)
    {
        ctx = std::make_shared<AttestationContext>();
    }

    if (ctr_drbg == nullptr)
    {
        ctr_drbg = std::make_shared<mbedtls::ctr_drbg>();
    }

    auto format_setting_vec = ctx->verifier->format_settings();
    *format_setting_len = format_setting_vec->size();
    *format_setting =
        static_cast<uint8_t*>(oe_host_malloc(*format_setting_len));
    memcpy(
        *format_setting,
        format_setting_vec->data(),
        format_setting_vec->size());

    ctx->this_pk = ctx->ecdh_ctx->make_public(*ctx->rand_ctx);
    *pk_len = ctx->this_pk.size();
    *pk = static_cast<uint8_t*>(oe_host_malloc(*pk_len));
    memcpy(*pk, ctx->this_pk.data(), ctx->this_pk.size());
}

void generate_evidence(
    const uint8_t* pk,
    size_t pk_len,
    const uint8_t* format,
    size_t format_len,
    uint8_t** evidence,
    size_t* evidence_len)
{
    ctx->peer_pk = v8(pk, pk + pk_len);
    ctx->ecdh_ctx->read_public(ctx->peer_pk);

    v8 claim(pk, pk + pk_len);
    claim.insert(claim.end(), ctx->this_pk.begin(), ctx->this_pk.end());

    v8 fs(format, format + format_len);
    auto evidence_vec = ctx->attester->get_evidence(fs, claim);

    *evidence_len = evidence_vec.size();
    *evidence = static_cast<uint8_t*>(oe_host_malloc(*evidence_len));
    memcpy(*evidence, evidence_vec.data(), evidence_vec.size());
}

auto finish_attestation(const uint8_t* data, size_t size) -> bool
{
    v8 evidence(data, data + size);
    auto claim = ctx->verifier->attest_attestation_evidence(evidence)
                     .custom_claims_buffer();

    const uint8_t* this_pk_ptr = claim.value + 0;
    const uint8_t* peer_pk_ptr = claim.value + ctx->this_pk.size();

    if (claim.value_size == ctx->this_pk.size() + ctx->peer_pk.size() &&
        memcmp(this_pk_ptr, ctx->this_pk.data(), ctx->this_pk.size()) == 0 &&
        memcmp(peer_pk_ptr, ctx->peer_pk.data(), ctx->peer_pk.size()) == 0)
    {
        auto secret = ctx->ecdh_ctx->calc_secret(*ctx->rand_ctx);
        std::array<uint8_t, mbedtls::aes::KEY_LEN_256 / mbedtls::BITS_PER_BYTE>
            session_key{0};

        mbedtls_sha256_ret(secret.data(), secret.size(), &session_key[0], 0);
        crypto_ctx = std::make_shared<aes_gcm_256>(session_key);

        return true;
    }

    ctx = nullptr;
    return false;
}

void generate_message(uint8_t** data, size_t* size)
{
    v8 dummy = {1, 2, 3, 4, 5, 6, 7, 8};
    auto output = crypto_ctx->encrypt(dummy, *ctr_drbg);

    *size = output.size();
    *data = static_cast<uint8_t*>(oe_host_malloc(output.size()));
    memcpy(*data, output.data(), output.size());
}

auto process_message(const uint8_t* data, size_t size) -> bool
{
    auto output = crypto_ctx->decrypt(data, size);
    return !output.empty();
}

void build_bloom_filter(
    const uint32_t* data,
    size_t length,
    uint8_t** output,
    size_t* output_size)
{
    HashSet bloom_filter;
    PRP prp;

    for (size_t i = 0; i < length; i++)
    {
        bloom_filter.insert(prp(data[i]));
    }

    const auto enc = crypto_ctx->encrypt(bloom_filter.data(), *ctr_drbg);

    *output_size = enc.size();
    *output = static_cast<uint8_t*>(oe_host_malloc(enc.size()));
    memcpy(*output, enc.data(), enc.size());
}

void match_bloom_filter(
    const uint32_t* data_key,
    const uint32_t* data_val,
    size_t size,
    const uint8_t* bloom_filter,
    size_t bloom_filter_size,
    const uint8_t* pubkey,
    size_t pubkey_size,
    uint8_t** output,
    size_t* output_size)
{
    HashSet input_filter(crypto_ctx->decrypt(bloom_filter, bloom_filter_size));
    PRP prp;

    PSI::Paillier paillier;
    paillier.load_pubkey(pubkey, pubkey_size);

    nlohmann::json hits = nlohmann::json::array();

    for (size_t i = 0; i < size; i++)
    {
        uint128_t key = prp(data_key[i]);
        if (input_filter.lookup(key))
        {
            auto enc = paillier.encrypt(data_val[i], *ctr_drbg).to_vector();
            if (enc.empty())
            {
                TRACE_ENCLAVE("enc size = %lx", enc.size());
                abort();
            }

            hits.push_back(nlohmann::json::array(
                {*reinterpret_cast<const KeyBin*>(&key), enc}));
        }
    }

    auto enc = crypto_ctx->encrypt(nlohmann::json::to_msgpack(hits), *ctr_drbg);

    *output_size = enc.size();
    *output = static_cast<uint8_t*>(oe_host_malloc(enc.size()));
    memcpy(*output, enc.data(), enc.size());
}

void aggregate(
    const uint32_t* data_key,
    const uint32_t* data_val,
    size_t size,
    const uint8_t* peer_data,
    size_t peer_data_size,
    const uint8_t* pubkey,
    size_t pubkey_size,
    uint8_t** output,
    size_t* output_size)
{
    // Decryption

    auto dec = crypto_ctx->decrypt(peer_data, peer_data_size);
    nlohmann::json peer = nlohmann::json::from_msgpack(dec.begin(), dec.end());

    // Build hash table

    PRP prp;
    HashTable hashing;

    for (size_t i = 0; i < size; i++)
    {
        hashing.insert(prp(data_key[i]), data_val[i]);
    }

    // Aggregate

    PSI::Paillier paillier;
    paillier.load_pubkey(pubkey, pubkey_size);

    nlohmann::json output_arr = nlohmann::json::array();
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
            output_arr.push_back(nlohmann::json::array(
                {pair[0],
                 paillier.add(peer_val, paillier.encrypt(val, *ctr_drbg))
                     .to_vector()}));
        }
    }

    auto enc = nlohmann::json::to_msgpack(output_arr);

    *output_size = enc.size();
    *output = static_cast<uint8_t*>(oe_host_malloc(enc.size()));
    memcpy(*output, enc.data(), enc.size());
}
