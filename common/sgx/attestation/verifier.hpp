#pragma once

#include <string>

#include <openenclave/attestation/verifier.h>

#include "claims.hpp"
#include "common/types.hpp"

class Verifier
{
    const oe_uuid_t* format_ptr;

  public:
    Verifier(const Verifier&) = delete;

    explicit Verifier(const oe_uuid_t* format_id);

    auto format_settings() -> std::string;

    auto verify_evidence(const std::string& evidence) -> Claims;
};
