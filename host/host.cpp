#ifndef SGX_MODE_SIM
#define SGX_MODE_HW
#endif

#include <iostream>
#include <map>
#include <vector>

#include <openenclave/host.h>
#include <boost/program_options.hpp>

#include "prng.hpp"

#include "enclave.hpp"

constexpr size_t TEST_SIZE = (1 << 20);

auto random_dataset() -> std::map<uint32_t, uint32_t>
{
    PRNG<uint32_t> prng;

    std::map<uint32_t, uint32_t> dataset;

    for (size_t i = 0; i < TEST_SIZE; i++)
    {
        auto k = prng();
        if (dataset.find(k) == dataset.end())
        {
            dataset[k] = 1;
        }
        else
        {
            dataset[k]++;
        }
    }

    return dataset;
}

auto main(int argc, const char* argv[]) -> int
{
    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s enclave_image_path\n", argv[0]);
        return EXIT_FAILURE;
    }

#ifdef SGX_MODE_SIM
    HelloworldEnclave enclave(argv[1], true);
#else
    HelloworldEnclave enclave(argv[1], false);
#endif

    std::vector<uint32_t> arr = {0};
    const size_t DATA_SIZE = 12;
    for (size_t i = 0; i < DATA_SIZE; i++)
    {
        arr.push_back(1);
    }

    enclave.helloworld(arr);

    return 0;
}
