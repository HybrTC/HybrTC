#pragma once

#include <map>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <openenclave/attestation/sgx/evidence.h>
#include <openenclave/attestation/verifier.h>
#include <openenclave/bits/result.h>

#include "claims.hpp"
#include "common/types.hpp"
#include "sgx/log.h"

class Verifier
{
    const oe_uuid_t* format_ptr;

  public:
    Verifier(const Verifier&) = delete;

    explicit Verifier(const oe_uuid_t* format_id) : format_ptr(format_id)
    {
        oe_verifier_initialize();
    }

    auto format_settings() -> v8
    {
        uint8_t* buffer = nullptr;
        size_t size = 0;

        oe_verifier_get_format_settings(format_ptr, &buffer, &size);

        v8 format_settings(buffer, buffer + size);

        oe_verifier_free_format_settings(buffer);

        return format_settings;
    }

    auto verify_evidence(const v8& evidence) -> Claims
    {
        oe_claim_t* claims = nullptr;
        size_t claims_length = 0;

        oe_result_t result = oe_verify_evidence(
            format_ptr, evidence.data(), evidence.size(), nullptr, 0, nullptr, 0, &claims, &claims_length);

        if (result != OE_OK)
        {
            TRACE_ENCLAVE("oe_verify_evidence -> %s", oe_result_str(result));
            return Claims(nullptr, 0);
        }

        auto claim_store = Claims(claims, claims_length);
        oe_free_claims(claims, claims_length);

        return claim_store;
    }

    ~Verifier()
    {
        oe_verifier_shutdown();
    }
};
