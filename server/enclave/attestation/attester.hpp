#pragma once

#include <map>
#include <memory>
#include <string>
#include <vector>

#include <openenclave/attestation/attester.h>
#include <openenclave/attestation/sgx/evidence.h>

#include "claims.hpp"
#include "common/types.hpp"

class Attester
{
    const oe_uuid_t* format_ptr;

  public:
    Attester(const Attester&) = delete;

    explicit Attester(const oe_uuid_t* format_id) : format_ptr(format_id)
    {
        oe_attester_initialize();
    }

    template <size_t N>
    auto get_evidence(const v8& format_settings, const a8<N>& custom_claims)
        -> v8
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

        v8 evidence(evidence_buf, evidence_buf + evidence_size);
        oe_free_evidence(evidence_buf);

        return evidence;
    }

    ~Attester()
    {
        oe_attester_shutdown();
    }
};
