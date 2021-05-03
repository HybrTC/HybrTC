#include <iostream>
#include <map>
#include <vector>

#include <openenclave/host.h>

#include "enclave.hpp"
#include "prng.hpp"

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

void hexdump(const char* name, const buffer& buf)
{
    printf("=== [%s]\t", name);

    for (size_t i = 0; i < buf.size; i++)
    {
        printf("%02x", buf.data[i]);
    }

    puts("");
}

auto main(int argc, const char* argv[]) -> int
{
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

    SPIEnclave enclave_a(argv[1], simulate);
    SPIEnclave enclave_b(argv[1], simulate);

    buffer pk_a;
    buffer format_setting_a;
    enclave_a.initialize_attestation(pk_a, format_setting_a);
    hexdump("pk_a", pk_a);

    buffer pk_b;
    buffer format_setting_b;
    enclave_b.initialize_attestation(pk_b, format_setting_b);
    hexdump("pk_b", pk_b);

    buffer evidence_a;
    enclave_a.generate_evidence(pk_b, format_setting_b, evidence_a);

    buffer evidence_b;
    enclave_b.generate_evidence(pk_a, format_setting_a, evidence_b);

    bool result_a = enclave_a.finish_attestation(evidence_b);
    bool result_b = enclave_b.finish_attestation(evidence_a);

    if (result_a && result_b)
    {
        puts("[+] attestation succeed");
    }
    else
    {
        puts("[-] attestation failed");
    }

    buffer ciphertext;
    enclave_a.generate_message(ciphertext);
    bool r = enclave_b.process_message(ciphertext);
    if (r)
    {
        puts("[+] process_message succeed");
    }
    else
    {
        puts("[+] process_message failed");
    }

    // constexpr size_t TEST_SIZE = (1 << 8);

    // auto ds1 = random_dataset<uint32_t, uint32_t>(TEST_SIZE);
    // auto ds2 = random_dataset<uint32_t, uint32_t>(TEST_SIZE);

    // puts("[+] enclave_a.helloworld(ds1.first);");
    // auto filtera = enclave_a.build_bloom_filter(ds1.first);
    // printf("filter_size = 0x%lx\n", filtera.size());

    // puts("[+] enclave_b.helloworld(ds2.first);");
    // auto filterb = enclave_b.build_bloom_filter(ds2.first);
    // printf("filter_size = 0x%lx\n", filterb.size());

    return 0;
}
