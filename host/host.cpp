#include <iostream>
#include <map>
#include <vector>

#include <openenclave/host.h>
#include <boost/program_options.hpp>

#include "prng.hpp"

#include "enclave.hpp"

#ifndef SGX_MODE_SIM
#define SGX_MODE_HW
#endif

template <class KT, class VT>
auto random_dataset(size_t size) -> std::pair<std::vector<KT>, std::vector<VT>>
{
    PRNG<uint32_t> prng;

    std::pair<std::vector<KT>, std::vector<VT>> dataset;

    for (size_t i = 0; i < size; i++)
    {
        dataset.first.push_back(prng());
        dataset.second.push_back(prng());
    }

    return dataset;
}

auto main(int argc, const char* argv[]) -> int
{
    constexpr size_t TEST_SIZE = (1 << 8);

    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s enclave_image_path\n", argv[0]);
        return EXIT_FAILURE;
    }

    bool simulate =
#ifdef SGX_MODE_SIM
        true;
#else
        false;
#endif

    HelloworldEnclave enclave_a(argv[1], simulate);
    HelloworldEnclave enclave_b(argv[1], simulate);

    auto ds1 = random_dataset<uint32_t, uint32_t>(TEST_SIZE);
    auto ds2 = random_dataset<uint32_t, uint32_t>(TEST_SIZE);

    puts("[+] enclave_a.helloworld(ds1.first);");
    enclave_a.helloworld(ds1.first);

    puts("[+] enclave_b.helloworld(ds2.first);");
    enclave_b.helloworld(ds2.first);

    return 0;
}
