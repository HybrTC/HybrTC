#include <cstdint>

#include "enclave.hpp"
#include "host/spdlog.hpp"

#include "helloworld_u.h"

#define CHECK(f, result)                                                                              \
    if ((result) != OE_OK)                                                                            \
    {                                                                                                 \
        SPDLOG_ERROR("calling into {} failed: result={} ({})", f, (result), oe_result_str((result))); \
        exit(EXIT_FAILURE);                                                                           \
    }

#define ECALL_IN                                      \
    {                                                 \
        SPDLOG_DEBUG("ECALL > {}", __FUNCTION__);      \
        timer(fmt::format("{}:start", __FUNCTION__)); \
    }

#define ECALL_OUT                                    \
    {                                                \
        timer(fmt::format("{}:done", __FUNCTION__)); \
        SPDLOG_DEBUG("ECALL < {}", __FUNCTION__);     \
        CHECK(__FUNCTION__, result);                 \
    }

PSIEnclave::PSIEnclave(const char* enclave_image_path, bool simulate, unsigned server_id, unsigned server_count)
{
    uint32_t flags = OE_ENCLAVE_FLAG_DEBUG;
    if (simulate)
    {
        flags |= OE_ENCLAVE_FLAG_SIMULATE;
    }

    oe_result_t result =
        oe_create_helloworld_enclave(enclave_image_path, OE_ENCLAVE_TYPE_AUTO, flags, nullptr, 0, &enclave_ptr);
    CHECK("oe_create_helloworld_enclave", result);

    initialize(server_id, server_count);
}

void PSIEnclave::initialize(unsigned server_id, unsigned server_count)
{
    ECALL_IN;
    oe_result_t result = ::initialize(enclave(), server_id, server_count);
    ECALL_OUT;
}

void PSIEnclave::verifier_generate_challenge(buffer& output)
{
    ECALL_IN;
    oe_result_t result = ::verifier_generate_challenge(enclave(), &output.data, &output.size);
    ECALL_OUT;
}

auto PSIEnclave::attester_generate_response(const v8& input, buffer& output) -> uint32_t
{
    uint32_t sid;

    ECALL_IN;
    oe_result_t result =
        ::attester_generate_response(enclave(), &sid, input.data(), input.size(), &output.data, &output.size);
    ECALL_OUT;

    return sid;
}

auto PSIEnclave::verifier_process_response(const buffer& input) -> uint32_t
{
    uint32_t sid;

    ECALL_IN;
    oe_result_t result = ::verifier_process_response(enclave(), &sid, input.data, input.size);
    ECALL_OUT;

    return sid;
}

void PSIEnclave::set_client_query(const v8& input, const v32& keys, const v32& values)
{
    ECALL_IN;
    oe_result_t result =
        ::set_client_query(enclave(), input.data(), input.size(), keys.data(), values.data(), keys.size());
    ECALL_OUT;
}

void PSIEnclave::gen_compute_request(buffer& bloom_filter)
{
    ECALL_IN;
    oe_result_t result = ::gen_compute_request(enclave(), &bloom_filter.data, &bloom_filter.size);
    ECALL_OUT;
}

auto PSIEnclave::pro_compute_request(const buffer& input, buffer& output) -> int
{
    int otype;
    ECALL_IN;
    oe_result_t result = ::pro_compute_request(enclave(), &otype, input.data, input.size, &output.data, &output.size);
    ECALL_OUT;
    return otype;
}

void PSIEnclave::pro_compute_response(const buffer& input, buffer& output)
{
    ECALL_IN;
    oe_result_t result = ::pro_compute_response(enclave(), input.data, input.size, &output.data, &output.size);
    ECALL_OUT;
}

void PSIEnclave::get_result(buffer& obuf)
{
    ECALL_IN;
    oe_result_t result = ::get_result(enclave(), &obuf.data, &obuf.size);
    ECALL_OUT;
}
