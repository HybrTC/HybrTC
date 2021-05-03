#pragma once

#include <cstring>
#include <memory>
#include <utility>
#include <vector>

#include <openenclave/attestation/custom_claims.h>
#include <openenclave/attestation/verifier.h>

class Claims
{
    oe_claim_t* claims;
    size_t claims_length;

    constexpr static oe_claim_t nan{
        .name = nullptr,
        .value = nullptr,
        .value_size = 0};

  public:
    Claims(const Claims&) = delete;

    Claims(oe_claim_t* claims, size_t claims_length)
        : claims(claims), claims_length(claims_length)
    {
    }

    auto find(const char* name) const -> const oe_claim_t&
    {
        for (size_t i = 0; i < claims_length; i++)
        {
            if (strcmp(claims[i].name, name) == 0)
            {
                return claims[i];
            }
        }
        return nan;
    }

    [[nodiscard]] auto custom_claims_buffer() const -> const oe_claim_t&
    {
        return find(OE_CLAIM_CUSTOM_CLAIMS_BUFFER);
    }

    ~Claims()
    {
        oe_free_claims(claims, claims_length);
    }
};
