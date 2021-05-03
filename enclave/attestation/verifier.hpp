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

class VerifierContext
{
    const oe_uuid_t* format_ptr;
    std::shared_ptr<std::vector<uint8_t>> format_settings_ptr = nullptr;

  public:
    VerifierContext(const VerifierContext&) = delete;

    explicit VerifierContext(const oe_uuid_t* format_id) : format_ptr(format_id)
    {
        oe_verifier_initialize();
    }

    auto format_settings() -> std::shared_ptr<std::vector<uint8_t>>
    {
        if (format_settings_ptr == nullptr)
        {
            uint8_t* format_settings = nullptr;
            size_t format_settings_size = 0;
            oe_verifier_get_format_settings(
                format_ptr, &format_settings, &format_settings_size);
            format_settings_ptr = std::make_shared<std::vector<uint8_t>>(
                format_settings, format_settings + format_settings_size);
            oe_verifier_free_format_settings(format_settings);
        }
        return format_settings_ptr;
    }

    auto attest_attestation_evidence(const std::vector<uint8_t>& evidence)
        -> Claims
    {
        oe_claim_t* claims = nullptr;
        size_t claims_length = 0;

        oe_result_t result = oe_verify_evidence(
            format_ptr,
            evidence.data(),
            evidence.size(),
            nullptr,
            0,
            nullptr,
            0,
            &claims,
            &claims_length);

        printf("claims_length=%lu\n", claims_length);

        if (result != OE_OK)
        {
            return Claims(nullptr, 0);
        }

        return Claims(claims, claims_length);
    }

    ~VerifierContext()
    {
        oe_verifier_shutdown();
    }
};
