#pragma once

#include <cstdint>
#include <mutex>
#include <vector>

#include <openenclave/host.h>

#include "common/types.hpp"
#include "timer.hpp"

struct buffer
{
    uint8_t* data = nullptr;
    size_t size = 0;

    buffer() = default;
    buffer(const buffer&) = delete;

    ~buffer()
    {
        if (data != nullptr)
        {
            free(data);
        }
    }
};

class SPIEnclave
{
    oe_enclave_t* enclave_ptr = nullptr;
    std::mutex lock;

    auto enclave() -> oe_enclave_t*
    {
        return enclave_ptr;
    }

    Timer timer;

  public:
    SPIEnclave(const char* enclave_image_path, bool simulate);

    ~SPIEnclave()
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

    auto verifier_process_response(const v8& input) -> uint32_t;

    void set_client_query(uint32_t sid, const v8& input, bool half, const v32& keys, const v32& values);

    void build_bloom_filter(uint32_t sid, buffer& bloom_filter);

    void match_bloom_filter(uint32_t sid, const v8& input, buffer& output);

    void aggregate(uint32_t sid, const v8& input);

    void get_result(uint32_t sid, buffer& obuf);
};
