#pragma once

#include <cstdint>
#include <utility>

#ifndef __OUTSIDE_ENCLAVE__
#include "attestation/attester.hpp"
#endif

#include "attestation/verifier.hpp"
#include "common/types.hpp"
#include "crypto/ecdh.hpp"
#include "crypto/gcm.hpp"
#include "crypto/sha256.hpp"
#include "sgx/session.hpp"

struct AttestationContext
{
    constexpr static oe_uuid_t format_id{OE_FORMAT_UUID_SGX_LOCAL_ATTESTATION};

    sptr<mbedtls::ctr_drbg> rand_ctx;
    mbedtls::ecdh ecdh;

    uint16_t vid = -1; // session id at verifier's side
    uint16_t aid = -1; // session id at attester's side

    v8 vpk; // verifier's pk
    v8 apk; // attester's pk

    explicit AttestationContext(const sptr<mbedtls::ctr_drbg>& rand_ctx)
        : rand_ctx(rand_ctx), ecdh(mbedtls::MBEDTLS_ECP_DP_SECP256R1, rand_ctx)
    {
    }

    [[nodiscard]] auto build_claims() const
    {
        mbedtls::sha256 hash;
        hash.update(vid);
        hash.update(vpk);
        hash.update(aid);
        hash.update(apk);
        return hash.finish();
    }

    auto complete_attestation() -> std::pair<uint32_t, sptr<PSI::Session>>
    {
        uint32_t sid = (vid << (sizeof(uint16_t) << 3)) | aid;

        mbedtls::sha256 hash;
        hash.update(vid);
        hash.update(aid);
        hash.update(ecdh.calc_secret());
        auto session_key = hash.finish();

        return {sid, std::make_shared<PSI::Session>(session_key)};
    }
};

#ifndef __OUTSIDE_ENCLAVE__
struct AttesterContext : public AttestationContext
{
    Attester core = Attester(&format_id);

    explicit AttesterContext(const sptr<mbedtls::ctr_drbg>& rand_ctx) : AttestationContext(rand_ctx)
    {
        this->apk = this->ecdh.make_public();
    }
};
#endif

struct VerifierContext : public AttestationContext
{
    Verifier core = Verifier(&format_id);

    explicit VerifierContext(const sptr<mbedtls::ctr_drbg>& rand_ctx) : AttestationContext(rand_ctx)
    {
        this->vpk = this->ecdh.make_public();
    }
};
