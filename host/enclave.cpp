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

void SPIEnclave::build_bloom_filter(
    const std::vector<uint32_t>& keys,
    buffer& bloom_filter)
{
    // build

    oe_result_t result = ::build_bloom_filter(
        enclave(),
        keys.data(),
        keys.size(),
        &bloom_filter.data,
        &bloom_filter.size);
    CHECK("build_bloom_filter", result);
}

void SPIEnclave::match_bloom_filter(
    const std::vector<uint32_t>& keys,
    const std::vector<uint32_t>& values,
    const buffer& bloom_filter,
    const std::vector<uint8_t>& pubkey,
    buffer& output)
{
    oe_result_t result = ::match_bloom_filter(
        enclave(),
        keys.data(),
        values.data(),
        keys.size(),
        bloom_filter.data,
        bloom_filter.size,
        pubkey.data(),
        pubkey.size(),
        &output.data,
        &output.size);
    CHECK("match_bloom_filter", result);
}
