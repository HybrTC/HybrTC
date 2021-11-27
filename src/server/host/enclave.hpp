#pragma once

#include <cstdint>
#include <mutex>
#include <vector>

#include <openenclave/host.h>

#include "common/types.hpp"
#include "host/timer.hpp"

struct buffer
{
    uint8_t* data = nullptr;
    size_t size = 0;

    buffer() = default;
    buffer(const buffer&) = delete;
};

class PSIEnclave
{
    oe_enclave_t* enclave_ptr = nullptr;

    auto enclave() -> oe_enclave_t*
    {
        return enclave_ptr;
    }

    Timer timer;

    void initialize(unsigned server_id, unsigned server_count);

  public:
    PSIEnclave(const char* enclave_image_path, bool simulate, unsigned server_id, unsigned server_count);

    ~PSIEnclave()
    {
        if (enclave_ptr != nullptr)
        {
            oe_terminate_enclave(enclave_ptr);
        }
    }

    auto get_timer() -> Timer&
    {
        return timer;
    }

    void verifier_generate_challenge(buffer& output);

    auto attester_generate_response(const v8& input, buffer& output) -> uint32_t;

    auto verifier_process_response(const buffer& input) -> uint32_t;

    // general
    void set_client_query(const v8& input, const v32& keys, const v32& values);

    // active
    void gen_compute_request(buffer& bloom_filter);

    // passive
    void pro_compute_request(const v8& input, buffer& output);

    // active
    void pro_compute_response(const v8& input);

    // active
    void get_result(buffer& obuf);
};
