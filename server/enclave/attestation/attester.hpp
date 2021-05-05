#pragma once

#include <map>
#include <memory>
#include <string>
#include <vector>

#include <openenclave/attestation/attester.h>
#include <openenclave/attestation/sgx/evidence.h>

#include "claims.hpp"

class Attester
{
    const oe_uuid_t* format_ptr;

  public:
    Attester(const Attester&) = delete;

    explicit Attester(const oe_uuid_t* format_id) : format_ptr(format_id)
    {
        oe_attester_initialize();
    }

    auto get_evidence(
        const std::vector<uint8_t>& format_settings,
        const std::vector<uint8_t>& custom_claims) -> std::vector<uint8_t>
    {
        uint8_t* evidence_buf = nullptr;
        size_t evidence_size;

        oe_get_evidence(
            format_ptr,
            0,
            custom_claims.data(),
            custom_claims.size(),
            format_settings.data(),
            format_settings.size(),
            &evidence_buf,
            &evidence_size,
            nullptr,
            nullptr);

        std::vector<uint8_t> evidence(
            evidence_buf, evidence_buf + evidence_size);
        oe_free_evidence(evidence_buf);

        return evidence;
    }

    ~Attester()
    {
        oe_attester_shutdown();
    }
};
