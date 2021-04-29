#include "enclave.hpp"

#include "helloworld_u.h"

#define CHECK(f, result)                                \
    if ((result) != OE_OK)                              \
    {                                                   \
        fprintf(                                        \
            stderr,                                     \
            "calling into %s failed: result=%u (%s)\n", \
            f,                                          \
            (result),                                   \
            oe_result_str((result)));                   \
        abort();                                        \
    }

SPIEnclave::SPIEnclave(const char* enclave_image_path, bool simulate)
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

    CHECK("oe_create_helloworld_enclave", result);
}

auto SPIEnclave::build_bloom_filter(const std::vector<uint32_t>& arr)
    -> std::vector<uint8_t>
{
    oe_result_t result;

    // build

    size_t filter_size = 0;
    result =
        ::build_bloom_filter(enclave(), &filter_size, arr.data(), arr.size());
    CHECK("build_bloom_filter", result);

    // get

    std::vector<uint8_t> filter(filter_size, 0);
    result = ::get_bloom_filter(enclave(), &filter[0], filter.size());
    CHECK("get_bloom_filter", result);

    return filter;
}
