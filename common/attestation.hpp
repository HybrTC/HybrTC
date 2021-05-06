#pragma once

#ifndef __OUTSIDE_ENCLAVE__
#include "attestation/attester.hpp"
#endif

#include "attestation/verifier.hpp"
#include "common/types.hpp"
#include "crypto/ecdh.hpp"
#include "crypto/gcm.hpp"
#include "crypto/sha256.hpp"

extern std::map<uint32_t, std::shared_ptr<mbedtls::aes_gcm_256>> sessions;
extern std::shared_ptr<mbedtls::ctr_drbg> ctr_drbg;

struct AttestationContext
{
    constexpr static oe_uuid_t format_id{OE_FORMAT_UUID_SGX_LOCAL_ATTESTATION};

    mbedtls::ecdh ecdh = mbedtls::ecdh(mbedtls::MBEDTLS_ECP_DP_SECP256R1);

    uint16_t vid = -1; // session id at verifier's side
    uint16_t aid = -1; // session id at attester's side

    v8 vpk; // verifier's pk
    v8 apk; // attester's pk

    [[nodiscard]] auto build_claims() const
    {
        mbedtls::sha256 hash;
        hash.update(vid);
        hash.update(vpk);
        hash.update(aid);
        hash.update(apk);
        return hash.finish();
    }

    auto complete_attestation()
    {
        mbedtls::sha256 hash;
        hash.update(vid);
        hash.update(aid);
        hash.update(ecdh.calc_secret(*ctr_drbg));
        auto session_key = hash.finish();

        auto crypto_ctx = std::make_shared<mbedtls::aes_gcm_256>(session_key);
        uint32_t sid = (vid << (sizeof(uint16_t) << 3)) | aid;

        sessions.insert({sid, crypto_ctx});
        return sid;
    }
};

#ifndef __OUTSIDE_ENCLAVE__
struct AttesterContext : public AttestationContext
{
    Attester core = Attester(&format_id);
};
#endif

struct VerifierContext : public AttestationContext
{
    Verifier core = Verifier(&format_id);
};
