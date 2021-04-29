#pragma once

#include <vector>

#include <openenclave/host.h>

class Enclave
{
  private:
    oe_enclave_t* enclave_ptr = nullptr;

  protected:
    auto enclave() -> oe_enclave_t*
    {
        return enclave_ptr;
    }

  public:
    Enclave(const char* enclave_image_path, bool simulate);

    ~Enclave()
    {
        if (enclave_ptr != nullptr)
        {
            oe_terminate_enclave(enclave_ptr);
        }
    }
};

class SPIEnclave : protected Enclave
{
  public:
    SPIEnclave(const char* enclave_image_path, bool simulate)
        : Enclave(enclave_image_path, simulate)
    {
    }

    auto build_bloom_filter(const std::vector<uint32_t>& arr)
        -> std::vector<uint8_t>;
};
