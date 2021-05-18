#include <cstdint>

#include "enclave.hpp"
#include "spdlog/fmt/bundled/core.h"
#include "utils/spdlog.hpp"

#include "helloworld_u.h"

#define CHECK(f, result)                                                                              \
    if ((result) != OE_OK)                                                                            \
    {                                                                                                 \
        SPDLOG_ERROR("calling into {} failed: result={} ({})", f, (result), oe_result_str((result))); \
        exit(EXIT_FAILURE);                                                                           \
    }

#define ECALL_IN                                      \
    {                                                 \
        lock.lock();                                  \
        timer(fmt::format("{}:start", __FUNCTION__)); \
    }

#define ECALL_OUT                                    \
    {                                                \
        timer(fmt::format("{}:done", __FUNCTION__)); \
        lock.unlock();                               \
    }

SPIEnclave::SPIEnclave(const char* enclave_image_path, bool simulate)
{
    uint32_t flags = OE_ENCLAVE_FLAG_DEBUG;
    if (simulate)
    {
        flags |= OE_ENCLAVE_FLAG_SIMULATE;
    }

    ECALL_IN;
    oe_result_t result =
        oe_create_helloworld_enclave(enclave_image_path, OE_ENCLAVE_TYPE_AUTO, flags, nullptr, 0, &enclave_ptr);
    ECALL_OUT;

    CHECK("oe_create_helloworld_enclave", result);
}

void SPIEnclave::verifier_generate_challenge(buffer& output)
{
    ECALL_IN;
    oe_result_t result = ::verifier_generate_challenge(enclave(), &output.data, &output.size);
    ECALL_OUT;

    CHECK("verifier_generate_challenge", result);
}

auto SPIEnclave::attester_generate_response(const v8& input, buffer& output) -> uint32_t
{
    uint32_t sid;

    ECALL_IN;
    oe_result_t result =
        ::attester_generate_response(enclave(), &sid, input.data(), input.size(), &output.data, &output.size);
    ECALL_OUT;

    CHECK("attester_generate_response", result);
    return sid;
}

auto SPIEnclave::verifier_process_response(const v8& input) -> uint32_t
{
    uint32_t sid;

    ECALL_IN;
    oe_result_t result = ::verifier_process_response(enclave(), &sid, input.data(), input.size());
    ECALL_OUT;

    CHECK("verifier_process_response", result);
    return sid;
}

void SPIEnclave::set_client_query(uint32_t sid, const v8& input, bool half, const v32& keys, const v32& values)
{
    ECALL_IN;
    oe_result_t result =
        ::set_client_query(enclave(), sid, input.data(), input.size(), half, keys.data(), values.data(), keys.size());
    ECALL_OUT;

    CHECK("set_client_query", result);
}

void SPIEnclave::build_bloom_filter(uint32_t sid, buffer& bloom_filter)
{
    ECALL_IN;
    oe_result_t result = ::build_bloom_filter(enclave(), sid, &bloom_filter.data, &bloom_filter.size);
    ECALL_OUT;

    CHECK("build_bloom_filter", result);
}

void SPIEnclave::match_bloom_filter(uint32_t sid, const v8& input, buffer& output)
{
    ECALL_IN;
    oe_result_t result = ::match_bloom_filter(enclave(), sid, input.data(), input.size(), &output.data, &output.size);
    ECALL_OUT;

    CHECK("match_bloom_filter", result);
}

void SPIEnclave::aggregate(uint32_t sid, const v8& input)
{
    ECALL_IN;
    oe_result_t result = ::aggregate(enclave(), sid, input.data(), input.size());
    ECALL_OUT;

    CHECK("aggregate", result);
}

void SPIEnclave::get_result(uint32_t sid, buffer& obuf)
{
    ECALL_IN;
    oe_result_t result = ::get_result(enclave(), sid, &obuf.data, &obuf.size);
    ECALL_OUT;

    CHECK("get_result", result);
}
