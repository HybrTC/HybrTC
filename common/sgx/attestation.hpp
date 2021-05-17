#pragma once

#include <cstdint>
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

    auto complete_attestation() -> std::pair<uint32_t, sptr<PSI::Session>>
    {
        uint32_t sid = (vid << (sizeof(uint16_t) << 3)) | aid;

        mbedtls::sha256 hash;
        hash.update(vid);
        hash.update(aid);
        hash.update(ecdh.calc_secret(*rand_ctx));
        auto session_key = hash.finish();

        return {sid, std::make_shared<PSI::Session>(session_key)};
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
