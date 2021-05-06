#include "enclave.hpp"
#include <cstdint>

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

void SPIEnclave::verifier_generate_challenge(buffer& output)
{
    oe_result_t result =
        ::verifier_generate_challenge(enclave(), &output.data, &output.size);

    CHECK("verifier_generate_challenge", result);
}

auto SPIEnclave::attester_generate_response(const v8& input, buffer& output)
    -> uint32_t
{
    uint32_t sid;

    oe_result_t result = ::attester_generate_response(
        enclave(),
        &sid,
        input.data(),
        input.size(),
        &output.data,
        &output.size);
    CHECK("attester_generate_response", result);
    return sid;
}

auto SPIEnclave::verifier_process_response(const v8& input) -> uint32_t
{
    uint32_t sid;
    oe_result_t result = ::verifier_process_response(
        enclave(), &sid, input.data(), input.size());
    CHECK("verifier_process_response", result);
    return sid;
}

// oe_result_t set_paillier_public_key(
//     oe_enclave_t* enclave,
//     uint32_t sid,
//     const uint8_t* ibuf,
//     size_t ilen);

void SPIEnclave::set_paillier_public_key(uint32_t sid, const v8& input)
{
    oe_result_t result =
        ::set_paillier_public_key(enclave(), sid, input.data(), input.size());
    CHECK("set_paillier_public_key", result);
}

void SPIEnclave::build_bloom_filter(
    uint32_t sid,
    const v32& keys,
    buffer& bloom_filter)
{
    // build

    oe_result_t result = ::build_bloom_filter(
        enclave(),
        sid,
        keys.data(),
        keys.size(),
        &bloom_filter.data,
        &bloom_filter.size);
    CHECK("build_bloom_filter", result);
}

void SPIEnclave::match_bloom_filter(
    uint32_t sid,
    const v32& keys,
    const v32& values,
    const v8& input,
    buffer& output)
{
    oe_result_t result = ::match_bloom_filter(
        enclave(),
        sid,
        keys.data(),
        values.data(),
        keys.size(),
        input.data(),
        input.size(),
        &output.data,
        &output.size);
    CHECK("match_bloom_filter", result);
}

void SPIEnclave::aggregate(
    uint32_t peer_sid,
    uint32_t client_sid,
    const v32& keys,
    const v32& values,
    const v8& input,
    buffer& output)
{
    oe_result_t result = ::aggregate(
        enclave(),
        peer_sid,
        client_sid,
        keys.data(),
        values.data(),
        keys.size(),
        input.data(),
        input.size(),
        &output.data,
        &output.size);
    CHECK("aggregate", result);
}
