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

class HelloworldEnclave : protected Enclave
{
  public:
    HelloworldEnclave(const char* enclave_image_path, bool simulate)
        : Enclave(enclave_image_path, simulate)
    {
    }

    void helloworld(const std::vector<uint32_t>& arr);
};
