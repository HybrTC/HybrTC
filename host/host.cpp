#include <cstdint>
#include <ctime>
#include <iostream>
#include <map>

#include <openenclave/host.h>

#include "bloom_filter.hpp"
#include "hash.hpp"
#include "prng.hpp"
#include "prp.hpp"

#include "helloworld_u.h"

constexpr size_t TEST_SIZE = (1 << 20);

std::map<uint32_t, uint32_t> random_dataset()
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

bool check_simulate_opt(int* argc, const char* argv[])
{
    for (int i = 0; i < *argc; i++)
    {
        if (strcmp(argv[i], "--simulate") == 0)
        {
            fprintf(stdout, "Running in simulation mode\n");
            memmove(&argv[i], &argv[i + 1], (*argc - i) * sizeof(char*));
            (*argc)--;
            return true;
        }
    }
    return false;
}

int main(int argc, const char* argv[])
{
    oe_result_t result;
    int ret = 1;
    oe_enclave_t* enclave = NULL;

    uint32_t flags = OE_ENCLAVE_FLAG_DEBUG;
    if (check_simulate_opt(&argc, argv))
    {
        flags |= OE_ENCLAVE_FLAG_SIMULATE;
    }

    if (argc != 2)
    {
        fprintf(
            stderr, "Usage: %s enclave_image_path [ --simulate  ]\n", argv[0]);
        goto exit;
    }

    result = oe_create_helloworld_enclave(
        argv[1], OE_ENCLAVE_TYPE_AUTO, flags, NULL, 0, &enclave);
    if (result != OE_OK)
    {
        fprintf(
            stderr,
            "oe_create_helloworld_enclave(): result=%u (%s)\n",
            result,
            oe_result_str(result));
        goto exit;
    }

    result = enclave_helloworld(enclave);
    if (result != OE_OK)
    {
        fprintf(
            stderr,
            "calling into enclave_helloworld failed: result=%u (%s)\n",
            result,
            oe_result_str(result));
        goto exit;
    }

    ret = 0;

exit:
    if (enclave)
        oe_terminate_enclave(enclave);

    return ret;
}
