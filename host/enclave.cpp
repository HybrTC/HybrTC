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

auto SPIEnclave::build_bloom_filter(const std::vector<uint32_t>& arr)
    -> std::vector<uint8_t>
{
    size_t filter_size = 0;
    oe_result_t result =
        ::build_bloom_filter(enclave(), &filter_size, arr.data(), arr.size());
    if (result != OE_OK)
    {
        fprintf(
            stderr,
            "calling into build_bloom_filter failed: result=%u (%s)\n",
            result,
            oe_result_str(result));
        abort();
    }

    std::vector<uint8_t> filter(filter_size, 0);

    result = ::get_bloom_filter(enclave(), &filter[0], filter.size());
    if (result != OE_OK)
    {
        fprintf(
            stderr,
            "calling into get_bloom_filter failed: result=%u (%s)\n",
            result,
            oe_result_str(result));
        abort();
    }

    return filter;
}
