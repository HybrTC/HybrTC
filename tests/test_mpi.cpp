#include <iostream>

#include "../common/crypto/bignum.hpp"
#include "../common/crypto/ctr_drbg.hpp"

auto main() -> int
{
    mbedtls::ctr_drbg ctr_drbg;
    mbedtls::mpi x = mbedtls::mpi::gen_rand(8, ctr_drbg);
    mbedtls::mpi e = mbedtls::mpi::gen_rand(8, ctr_drbg);
    mbedtls::mpi p = mbedtls::mpi::gen_prime(12, ctr_drbg);

    auto r = x.exp_mod(e, p);
    auto s = r.write_string(16);

    std::cout << s << std::endl;
}
