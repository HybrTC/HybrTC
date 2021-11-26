#include <memory>
#include <mutex>

#include <openenclave/attestation/sgx/evidence.h>
#include <openenclave/attestation/verifier.h>
#include <openenclave/bits/result.h>

#include "claims.hpp"
#include "common/types.hpp"
#include "sgx/log.h"

#include "verifier.hpp"

class VerifierInit
{
  public:
    VerifierInit()
    {
        oe_verifier_initialize();
    }

    ~VerifierInit()
    {
        oe_verifier_shutdown();
    }
};

static std::shared_ptr<VerifierInit> init = nullptr;
static std::mutex init_lock;

Verifier::Verifier(const oe_uuid_t* format_id) : format_ptr(format_id)
{
    init_lock.lock();
    if (init == nullptr)
    {
        init = std::make_shared<VerifierInit>();
    }
    init_lock.unlock();
}

auto Verifier::format_settings() -> std::string
{
    uint8_t* buffer = nullptr;
    size_t size = 0;

    oe_result_t ret = oe_verifier_get_format_settings(format_ptr, &buffer, &size);
    if (ret != OE_OK)
    {
        TRACE_ENCLAVE("oe_verifier_get_format_settings returns %s", oe_result_str(ret));
        std::abort();
    }

    std::string format_settings(buffer, buffer + size);

    oe_verifier_free_format_settings(buffer);

    return format_settings;
}

auto Verifier::verify_evidence(const std::string& evidence) -> Claims
{
    oe_claim_t* claims = nullptr;
    size_t claims_length = 0;

    oe_result_t result = oe_verify_evidence(
        format_ptr, u8p(evidence.data()), evidence.size(), nullptr, 0, nullptr, 0, &claims, &claims_length);

    if (result != OE_OK)
    {
        if (result != OE_TCB_LEVEL_INVALID) // this is a workaround for our outdate platform
        {
            TRACE_ENCLAVE("oe_verify_evidence -> %s", oe_result_str(result));
            abort();
        }
        return Claims(nullptr, 0);
    }

    auto claim_store = Claims(claims, claims_length);
    oe_free_claims(claims, claims_length);

    return claim_store;
}
