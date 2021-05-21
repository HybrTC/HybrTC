#pragma once

#include <cstring>
#include <map>
#include <memory>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include <openenclave/attestation/custom_claims.h>
#include <openenclave/attestation/verifier.h>

#include "common/types.hpp"
#include "sgx/log.h"

class Claims
{
    std::map<std::string, v8> claim_store;

  public:
    Claims(oe_claim_t* claims, size_t claims_length)
    {
        for (size_t i = 0; i < claims_length; i++)
        {
            claim_store.insert({claims[i].name, v8(claims[i].value, claims[i].value + claims[i].value_size)});
        }
    }

    [[nodiscard]] auto custom_claims_buffer() const -> const v8&
    {
        auto it = claim_store.find(OE_CLAIM_CUSTOM_CLAIMS_BUFFER);
        if (it == claim_store.end())
        {
            throw std::runtime_error("Cannot find OE_CLAIM_CUSTOM_CLAIMS_BUFFER");
        }

        return it->second;
    }
};
