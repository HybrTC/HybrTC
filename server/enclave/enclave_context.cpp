#include <mbedtls/ctr_drbg.h>
#include <openenclave/enclave.h>
#include <cstddef>
#include <nlohmann/json.hpp>

#include "enclave_context.hpp"
#include "sgx/attestation.hpp"
#include "sgx/session.hpp"

using nlohmann::json;

EnclaveContext::EnclaveContext() : rand_ctx(std::make_shared<mbedtls::ctr_drbg>())
{
    v8 custom;
    custom.resize(MBEDTLS_CTR_DRBG_KEYSIZE);
    oe_random(&custom[0], custom.size());
    rand_ctx->seed(custom);
}

void EnclaveContext::dump(const v8& bytes, uint8_t** obuf, size_t* olen)
{
    *olen = bytes.size();
    *obuf = u8p(oe_host_malloc(bytes.size()));
    memcpy(*obuf, bytes.data(), bytes.size());
}

void EnclaveContext::dump_enc(u32 sid, const v8& bytes, uint8_t** obuf, size_t* olen)
{
    auto cipher = session(sid).cipher();
    size_t len = cipher.encrypt_size(bytes.size());

    *olen = len;
    *obuf = u8p(oe_host_malloc(len));

    cipher.encrypt(*obuf, *olen, bytes.data(), bytes.size(), *rand_ctx);
}

auto EnclaveContext::rand_ptr() -> sptr<mbedtls::ctr_drbg>
{
    return rand_ctx;
}

auto EnclaveContext::rand() -> mbedtls::ctr_drbg&
{
    return *rand_ctx;
}

void EnclaveContext::new_session(u32 sid, sptr<PSI::Session> session, const AttestationContext& ctx)
{
    session_lock.lock();
    if (sessions.find(sid) != sessions.end())
    {
        (void)(ctx);
        TRACE_ENCLAVE("session id collision: vid=%04x aid=%04x sid=%08x", ctx.vid, ctx.aid, sid);
        abort();
    }
    else
    {
        sessions.insert({sid, std::move(session)});
    }
    session_lock.unlock();
}

auto EnclaveContext::session(u32 session_id) -> PSI::Session&
{
    session_lock.lock();
    auto it = sessions.find(session_id);
    if (it == sessions.end())
    {
        TRACE_ENCLAVE("cannot find session: sid=%08x", session_id);
        for (auto& [key, _] : sessions)
        {
            (void)(key);
            TRACE_ENCLAVE("existing session: sid=%08x", key);
        }
        abort();
    }
    auto ret = it->second;
    session_lock.unlock();

    return *ret;
}

void EnclaveContext::verifier_generate_challenge(u8** obuf, size_t* olen)
{
    /* initialize verifier context */
    auto ctx = std::make_shared<VerifierContext>(rand_ctx);

    /* set verifier id; generate and dump ephemeral public key */
    ctx->vid = verifiers.size();
    verifiers.push_back(ctx);

    /* generate output object */
    auto json = json::object({{"vid", ctx->vid}, {"vpk", ctx->vpk}, {"format_settings", ctx->core.format_settings()}});

    dump(json::to_msgpack(json), obuf, olen);
}

auto EnclaveContext::attester_generate_response(const u8* ibuf, size_t ilen, u8** obuf, size_t* olen) -> u32
{
    /* initialize attester context */
    AttesterContext ctx(rand_ctx);

    /* set attester id; generate and dump ephemeral public key */
    ctx.aid = rand_ctx->rand<decltype(ctx.aid)>();

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
    auto json = json::object({{"vid", ctx.vid}, {"aid", ctx.aid}, {"apk", ctx.apk}, {"evidence", evidence}});

    dump(json::to_msgpack(json), obuf, olen);

    /* build crypto context */
    auto [sid, session] = ctx.complete_attestation();
    new_session(sid, session, ctx);

    return sid;
}

auto EnclaveContext::verifier_process_response(const u8* ibuf, size_t ilen) -> u32
{
    /* deserialize and handle input */
    auto input = json::from_msgpack(ibuf, ibuf + ilen);

    auto ctx = verifiers[input["vid"].get<uint16_t>()]; // load verifier context
    ctx->aid = input["aid"].get<uint16_t>();            // set attester id
    ctx->apk = input["apk"].get<v8>();                  // set attester pubkey
    auto evidence = input["evidence"].get<v8>();        // load attestation evidence

    /* set vpk in ecdh context */
    ctx->ecdh.read_public(ctx->apk);

    /* verify evidence */
    auto claims = ctx->core.verify_evidence(evidence);

#if 0
    // this is a workaround for our outdate platform

    /* compare claims: (1) size (2) compare content in constant time */
    auto claim = claims.custom_claims_buffer();
    auto claim_ = ctx->build_claims();

    if (claim_.size() != claim.size())
    {
        TRACE_ENCLAVE("claim doesn't match (1): %lu %lu", claim_.size(), claim.size());
        abort();
    }

    unsigned result = 0;
    for (size_t i = 0; i < claim_.size() && i < claim.size(); i++)
    {
        result += (claim_[i] ^ claim[i]);
    }
    if (result != 0)
    {
        TRACE_ENCLAVE("claim doesn't match (2)");
        abort();
    }
#else
    (void)(claims);
#endif

    /* build crypto context and free verifier context */
    auto [sid, session] = ctx->complete_attestation();
    new_session(sid, session, *ctx);
    verifiers[ctx->vid] = nullptr;

    return sid;
}
