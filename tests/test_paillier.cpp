#include <iostream>

#include "../common/crypto/ctr_drbg.hpp"
#include "../common/paillier.hpp"

int main()
{
    mbedtls::ctr_drbg ctr_drbg;

    PSI::Paillier homo_crypto;
    homo_crypto.keygen(512, ctr_drbg);

    auto x1 = homo_crypto.encrypt(mbedtls::mpi(12), ctr_drbg);
    auto x2 = homo_crypto.encrypt(mbedtls::mpi(18), ctr_drbg);

    auto se = homo_crypto.add(x1, x2);
    auto s = homo_crypto.decrypt(se);

    std::cout << s.write_string(10) << std::endl;
}
