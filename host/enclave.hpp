#pragma once

#include <vector>

#include <openenclave/host.h>

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

    auto build_bloom_filter(const std::vector<uint32_t>& arr)
        -> std::vector<uint8_t>;
};
