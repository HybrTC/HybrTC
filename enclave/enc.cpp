#include <array>
#include <cstdio>
#include <cstring>
#include <memory>
#include <vector>

#include <mbedtls/sha256.h>
#include <nlohmann/json.hpp>

#include "attestation/attester.hpp"
#include "attestation/verifier.hpp"
#include "bloom_filter.hpp"
#include "crypto/ctr_drbg.hpp"
#include "crypto/ecdh.hpp"
#include "crypto/gcm.hpp"
#include "log.h"
#include "paillier.hpp"
#include "prp.hpp"

#include "helloworld_t.h"

constexpr uint32_t FILTER_POWER_BITS = 24;

void hexdump(const char* name, const std::vector<uint8_t>& bytes)
{
    printf("=== [%s]\t", name);
    for (auto b : bytes)
    {
        printf("%02x", b);
    }
    puts("");
}

template <size_t N>
void hexdump(const char* name, const std::array<uint8_t, N>& bytes)
{
    printf("=== [%s]\t", name);
    for (auto b : bytes)
    {
        printf("%02x", b);
    }
    puts("");
}

struct AttestationContext
{
    constexpr static oe_uuid_t format_id{OE_FORMAT_UUID_SGX_LOCAL_ATTESTATION};

    std::shared_ptr<Attester> attester = std::make_shared<Attester>(&format_id);
    std::shared_ptr<Verifier> verifier = std::make_shared<Verifier>(&format_id);

    std::shared_ptr<mbedtls::ctr_drbg> rand_ctx =
        std::make_shared<mbedtls::ctr_drbg>();
    std::shared_ptr<mbedtls::ecdh> ecdh_ctx =
        std::make_shared<mbedtls::ecdh>(mbedtls::MBEDTLS_ECP_DP_SECP256R1);

    std::vector<uint8_t> this_pk;
    std::vector<uint8_t> peer_pk;
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
    ctx->peer_pk = std::vector<uint8_t>(pk, pk + pk_len);
    ctx->ecdh_ctx->read_public(ctx->peer_pk);

    std::vector<uint8_t> claim(pk, pk + pk_len);
    claim.insert(claim.end(), ctx->this_pk.begin(), ctx->this_pk.end());

    std::vector<uint8_t> fs(format, format + format_len);
    auto evidence_vec = ctx->attester->get_evidence(fs, claim);

    *evidence_len = evidence_vec.size();
    *evidence = static_cast<uint8_t*>(oe_host_malloc(*evidence_len));
    memcpy(*evidence, evidence_vec.data(), evidence_vec.size());
}

auto finish_attestation(const uint8_t* data, size_t size) -> bool
{
    std::vector<uint8_t> evidence(data, data + size);
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
    std::vector<uint8_t> dummy = {1, 2, 3, 4, 5, 6, 7, 8};
    auto output = crypto_ctx->encrypt(dummy, *ctr_drbg);

    *size = output.size();
    *data = static_cast<uint8_t*>(oe_host_malloc(output.size()));
    memcpy(*data, output.data(), output.size());
}

auto process_message(const uint8_t* data, size_t size) -> bool
{
    std::vector<uint8_t> input(data, data + size);
    auto output = crypto_ctx->decrypt(input);
    return !output.empty();
}

void build_bloom_filter(
    const uint32_t* data,
    size_t length,
    uint8_t** output,
    size_t* output_size)
{
    BloomFilter<FILTER_POWER_BITS, 4> bloom_filter;
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
    uint8_t** output,
    size_t* output_size)
{
    std::vector<uint8_t> input(bloom_filter, bloom_filter + bloom_filter_size);
    BloomFilter<FILTER_POWER_BITS, 4> input_filter(crypto_ctx->decrypt(input));
    PRP prp;

    PSI::Paillier paillier;
    // TODO(jiamin): pailiar encryption
    paillier.keygen(2048, *ctr_drbg);

    nlohmann::json hits = nlohmann::json::array();

    for (size_t i = 0; i < size; i++)
    {
        auto key = prp(data_key[i]);
        if (input_filter.lookup(key))
        {
            hits.push_back(nlohmann::json::array(
                {key, paillier.encrypt(data_val[i], *ctr_drbg)}));
        }
    }

    auto enc = crypto_ctx->encrypt(nlohmann::json::to_msgpack(hits), *ctr_drbg);

    *output_size = enc.size();
    *output = static_cast<uint8_t*>(oe_host_malloc(enc.size()));
    memcpy(*output, enc.data(), enc.size());
}
