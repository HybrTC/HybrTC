#include "enclave.hpp"

#include "helloworld_u.h"

Enclave::Enclave(const char* enclave_image_path, bool simulate)
{
    uint32_t flags = OE_ENCLAVE_FLAG_DEBUG;
    if (simulate)
    {
        flags |= OE_ENCLAVE_FLAG_SIMULATE;
    }

    oe_result_t result = oe_create_helloworld_enclave(
        enclave_image_path,
        OE_ENCLAVE_TYPE_AUTO,
        flags,
        nullptr,
        0,
        &enclave_ptr);

    if (result != OE_OK)
    {
        fprintf(
            stderr,
            "oe_create_helloworld_enclave(): result=%u (%s)\n",
            result,
            oe_result_str(result));
        abort();
    }
}

void HelloworldEnclave::helloworld(const std::vector<uint32_t>& arr)
{
    oe_result_t result = enclave_helloworld(enclave(), arr.data(), arr.size());
    if (result != OE_OK)
    {
        fprintf(
            stderr,
            "calling into enclave_helloworld failed: result=%u (%s)\n",
            result,
            oe_result_str(result));
        abort();
    }
}
