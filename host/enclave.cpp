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

// public void initialize_attestation( [out] uint8_t** pk,
//                                     [out] size_t* pk_len,
//                                     [out] uint8_t** format_setting,
//                                     [out] size_t* format_setting_len);

// public void generate_evidence(      [in, size=pk_len] uint8_t* pk,
//                                     size_t pk_len,
//                                     [in, size=format_len] uint8_t* format,
//                                     size_t format_len,
//                                     [out] uint8_t** evidence,
//                                     [out] size_t* evidence_len);

// public bool finish_attestation(     [in, size=size] uint8_t* data,
//                                     size_t size);

// public void generate_message(       [out] uint8_t** data,
//                                     [out] size_t*  size);

// public bool process_message(        [in, count=size] uint8_t* data,
//                                     size_t  size);

void SPIEnclave::initialize_attestation(buffer& pk, buffer& format_setting)
{
    oe_result_t result = ::initialize_attestation(
        enclave(),
        &pk.data,
        &pk.size,
        &format_setting.data,
        &format_setting.size);

    CHECK("initialize_attestation", result);
}

void SPIEnclave::generate_evidence(
    const buffer& pk,
    const buffer& format_setting,
    buffer& evidence)
{
    oe_result_t result = ::generate_evidence(
        enclave(),
        pk.data,
        pk.size,
        format_setting.data,
        format_setting.size,
        &evidence.data,
        &evidence.size);
    CHECK("generate_evidence", result);
}

auto SPIEnclave::finish_attestation(const buffer& evidence) -> bool
{
    bool ret;
    oe_result_t result =
        ::finish_attestation(enclave(), &ret, evidence.data, evidence.size);
    CHECK("finish_attestation", result);
    return ret;
}

void SPIEnclave::generate_message(buffer& ciphertext)
{
    oe_result_t result =
        ::generate_message(enclave(), &ciphertext.data, &ciphertext.size);
    CHECK("generate_message", result);
}

auto SPIEnclave::process_message(const buffer& ciphertext) -> bool
{
    bool ret;
    oe_result_t result =
        ::process_message(enclave(), &ret, ciphertext.data, ciphertext.size);
    CHECK("process_message", result);
    return ret;
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
