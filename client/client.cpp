
#include <nlohmann/json.hpp>

#include <openenclave/host.h>

#include "crypto/ctr_drbg.hpp"
#include "paillier.hpp"

auto main(int argc, const char* argv[]) -> int
{
    OE_UNUSED(argc);
    OE_UNUSED(argv);

    mbedtls::ctr_drbg ctr_drbg;

    PSI::Paillier homo_crypto;
    homo_crypto.keygen(512, ctr_drbg);
    auto pubkey = homo_crypto.dump_pubkey();

    return 0;
}
