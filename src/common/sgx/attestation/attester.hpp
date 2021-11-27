#pragma once

#include <string>

#include <openenclave/attestation/attester.h>

#include "common/types.hpp"
#include "sgx/log.h"

class Attester
{
    const oe_uuid_t* format_ptr;

  public:
    Attester(const Attester&) = delete;

    explicit Attester(const oe_uuid_t* format_id);

    template <size_t N>
    auto get_evidence(const std::string& format_settings, const a8<N>& custom_claims) -> std::string
    {
        uint8_t* evidence_buf = nullptr;
        size_t evidence_size;

        oe_result_t result = oe_get_evidence(
            format_ptr,
            0,
            custom_claims.data(),
            custom_claims.size(),
            format_settings.empty() ? nullptr : format_settings.data(),
            format_settings.size(),
            &evidence_buf,
            &evidence_size,
            nullptr,
            nullptr);

        if (result != OE_OK)
        {
            TRACE_ENCLAVE("oe_get_evidence returns %s", oe_result_str(result));
            std::abort();
        }

        std::string evidence(evidence_buf, evidence_buf + evidence_size);
        oe_free_evidence(evidence_buf);

        return evidence;
    }
};
