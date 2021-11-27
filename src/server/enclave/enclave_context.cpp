#include <mbedtls/ctr_drbg.h>
#include <openenclave/enclave.h>
#include <cstddef>
#include <cstdint>

#include "common/types.hpp"
#include "enclave_context.hpp"
#include "msg_pb.h"
#include "sgx/attestation.hpp"
#include "sgx/session.hpp"

EnclaveContext::EnclaveContext(unsigned server_id, unsigned server_count)
    : rand_ctx(std::make_shared<mbedtls::ctr_drbg>()), id(server_id), count(server_count)
{
    v8 custom;
    custom.resize(MBEDTLS_CTR_DRBG_KEYSIZE);
    oe_random(&custom[0], custom.size());
    rand_ctx->seed(custom);
}

void EnclaveContext::dump(const std::string& bytes, uint8_t** obuf, size_t* olen)
{
    *olen = bytes.size();
    *obuf = u8p(oe_host_malloc(bytes.size()));
    memcpy(*obuf, bytes.data(), bytes.size());
}

void EnclaveContext::dump(const v8& bytes, uint8_t** obuf, size_t* olen)
{
    *olen = bytes.size();
    *obuf = u8p(oe_host_malloc(bytes.size()));
    memcpy(*obuf, bytes.data(), bytes.size());
}

void EnclaveContext::dump_enc(u32 sid, const std::string& bytes, uint8_t** obuf, size_t* olen)
{
    auto cipher = session(sid).cipher();
    size_t len = cipher.encrypt_size(bytes.size());

    *olen = len;
    *obuf = u8p(oe_host_malloc(len));

    cipher.encrypt(*obuf, *olen, u8p(bytes.data()), bytes.size(), *rand_ctx);
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
    /* Assuming only one verifier session */

    /* initialize verifier context */
    verifier = std::make_shared<VerifierContext>(rand_ctx);
    verifier->vid = id;

    /* set verifier id; generate and dump ephemeral public key */
    // ctx->vid = verifiers.size();
    // verifiers.push_back(ctx);

    TRACE_ENCLAVE("NEW VERIFIER@SERVER WITH ID %u", verifier->vid);

    /* generate output object */
    hybrtc::AttestationChallenge challenge;
    challenge.set_verifier_id(verifier->vid);
    challenge.set_verifier_pk(verifier->vpk);
    challenge.set_format_settings(verifier->core.format_settings());

    dump(challenge.SerializeAsString(), obuf, olen);
}

auto EnclaveContext::attester_generate_response(const u8* ibuf, size_t ilen, u8** obuf, size_t* olen) -> u32
{
    /* initialize attester context */
    AttesterContext ctx(rand_ctx);

    /* set attester id; generate and dump ephemeral public key */
    ctx.aid = rand_ctx->rand<decltype(ctx.aid)>();

    /* deserialize and handle input */

    hybrtc::AttestationChallenge input;
    input.ParseFromArray(ibuf, static_cast<int>(ilen));

    ctx.vid = input.verifier_id();            // set verifier id
    ctx.vpk = input.verifier_pk();            // set peer pk
    const auto& fs = input.format_settings(); // load format settings

    /* set vpk in ecdh context */
    ctx.ecdh.read_public(u8p(ctx.vpk.data()), ctx.vpk.size());

    /* build claims and generate evidence*/
    auto evidence = ctx.core.get_evidence(fs, ctx.build_claims());

    /* generate output object */
    hybrtc::AttestationResponse response;
    response.set_verifier_id(ctx.vid);
    response.set_attester_id(ctx.aid);
    response.set_attester_pk(ctx.apk);
    response.set_evidence(evidence);

    dump(response.SerializeAsString(), obuf, olen);

    /* build crypto context */
    auto [sid, session] = ctx.complete_attestation();
    new_session(sid, session, ctx);

    return sid;
}

auto EnclaveContext::verifier_process_response(const u8* ibuf, size_t ilen) -> u32
{
    /* deserialize and handle input */
    hybrtc::AttestationResponse input;
    input.ParseFromArray(ibuf, static_cast<int>(ilen));

    if (input.verifier_id() != id)
    {
        TRACE_ENCLAVE("Verifier ID mismatch");
        abort();
    }

    auto ctx = verifier;                     // load verifier context
    ctx->aid = input.attester_id();          // set attester id
    ctx->apk = input.attester_pk();          // set attester pubkey
    const auto& evidence = input.evidence(); // load attestation evidence

    /* set vpk in ecdh context */
    ctx->ecdh.read_public(u8p(ctx->apk.data()), ctx->apk.size());

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
    verifier = nullptr;

    return sid;
}
