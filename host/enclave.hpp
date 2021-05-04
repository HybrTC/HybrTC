#pragma once

#include <cstdint>
#include <vector>

#include <openenclave/host.h>

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

    auto enclave() -> oe_enclave_t*
    {
        return enclave_ptr;
    }

  public:
    SPIEnclave(const char* enclave_image_path, bool simulate);

    ~SPIEnclave()
    {
        if (enclave_ptr != nullptr)
        {
            oe_terminate_enclave(enclave_ptr);
        }
    }

    void initialize_attestation(buffer& pk, buffer& format_setting);

    void generate_evidence(
        const buffer& pk,
        const buffer& format_setting,
        buffer& evidence);

    auto finish_attestation(const buffer& evidence) -> bool;

    void generate_message(buffer& ciphertext);

    auto process_message(const buffer& ciphertext) -> bool;

    void build_bloom_filter(
        const std::vector<uint32_t>& keys,
        buffer& bloom_filter);

    void match_bloom_filter(
        const std::vector<uint32_t>& keys,
        const std::vector<uint32_t>& values,
        const buffer& bloom_filter,
        const std::vector<uint8_t>& pubkey,
        buffer& output);
};
