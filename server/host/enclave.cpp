#include <cstdint>

#include "enclave.hpp"
#include "utils/spdlog.hpp"

#include "helloworld_u.h"

#define CHECK(f, result)                              \
    if ((result) != OE_OK)                            \
    {                                                 \
        SPDLOG_ERROR(                                 \
            "calling into {} failed: result={} ({})", \
            f,                                        \
            (result),                                 \
            oe_result_str((result)));                 \
        exit(EXIT_FAILURE);                           \
    }

SPIEnclave::SPIEnclave(const char* enclave_image_path, bool simulate)
{
    uint32_t flags = OE_ENCLAVE_FLAG_DEBUG;
    if (simulate)
    {
        flags |= OE_ENCLAVE_FLAG_SIMULATE;
    }

    lock.lock();
    oe_result_t result = oe_create_helloworld_enclave(
        enclave_image_path,
        OE_ENCLAVE_TYPE_AUTO,
        flags,
        nullptr,
        0,
        &enclave_ptr);
    CHECK("oe_create_helloworld_enclave", result);
    lock.unlock();
}

void SPIEnclave::verifier_generate_challenge(buffer& output)
{
    lock.lock();
    oe_result_t result =
        ::verifier_generate_challenge(enclave(), &output.data, &output.size);

    CHECK("verifier_generate_challenge", result);
    lock.unlock();
}

auto SPIEnclave::attester_generate_response(const v8& input, buffer& output)
    -> uint32_t
{
    uint32_t sid;

    lock.lock();
    oe_result_t result = ::attester_generate_response(
        enclave(),
        &sid,
        input.data(),
        input.size(),
        &output.data,
        &output.size);
    CHECK("attester_generate_response", result);
    lock.unlock();
    return sid;
}

auto SPIEnclave::verifier_process_response(const v8& input) -> uint32_t
{
    uint32_t sid;
    lock.lock();
    oe_result_t result = ::verifier_process_response(
        enclave(), &sid, input.data(), input.size());
    CHECK("verifier_process_response", result);
    lock.unlock();
    return sid;
}

void SPIEnclave::set_client_query(
    uint32_t sid,
    const v8& input,
    bool half,
    const v32& keys,
    const v32& values)
{
    lock.lock();
    oe_result_t result = ::set_client_query(
        enclave(),
        sid,
        input.data(),
        input.size(),
        half,
        keys.data(),
        values.data(),
        keys.size());
    CHECK("set_client_query", result);
    lock.unlock();
}

void SPIEnclave::build_bloom_filter(uint32_t sid, buffer& bloom_filter)
{
    lock.lock();
    oe_result_t result = ::build_bloom_filter(
        enclave(), sid, &bloom_filter.data, &bloom_filter.size);
    CHECK("build_bloom_filter", result);
    lock.unlock();
}

void SPIEnclave::match_bloom_filter(
    uint32_t sid,
    const v8& input,
    buffer& output)
{
    lock.lock();
    oe_result_t result = ::match_bloom_filter(
        enclave(), sid, input.data(), input.size(), &output.data, &output.size);
    CHECK("match_bloom_filter", result);
    lock.unlock();
}

void SPIEnclave::aggregate(
    uint32_t peer_sid,
    uint32_t client_sid,
    const v8& input,
    buffer& output)
{
    lock.lock();
    oe_result_t result = ::aggregate(
        enclave(),
        peer_sid,
        client_sid,
        input.data(),
        input.size(),
        &output.data,
        &output.size);
    CHECK("aggregate", result);
    lock.unlock();
}
