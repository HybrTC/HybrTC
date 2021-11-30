#include <cstdint>
#include <cstdio>
#include <fstream>
#include <iostream>
#include <iterator>
#include <map>
#include <utility>

#include <nlohmann/json.hpp>

#include "crypto/ctr_drbg.hpp"
#include "crypto/gcm.hpp"
#include "enclave/psi/cuckoo_hashing.hpp"
#include "enclave/psi/prp.hpp"
#include "host/spdlog.hpp"
#include "host/timer.hpp"
#include "prng.hpp"
#include "spdlog/spdlog.h"

using nlohmann::json;

constexpr static u32 CH_LOG_LENGTH = 17;
constexpr static u32 CH_LOG_DEPTH = 2;
constexpr static u32 NUMBER_OF_HASHES = 4;
using HashTable = CuckooHashing<NUMBER_OF_HASHES>;

auto test(PRP& prp, mbedtls::aes_gcm_256& cipher, mbedtls::ctr_drbg& ctr_drbg)
{
    Timer timer;

    PRNG<u32> vPrng;

    auto key = vPrng();
    auto val = vPrng();

    timer("prp:start");
    prp(key);
    timer("prp:done");

    timer("enc:start");
    cipher.encrypt(reinterpret_cast<const uint8_t*>(&val), sizeof(val), ctr_drbg);
    timer("enc:done");

    return timer.to_json();
}

auto main() -> int
{
    PRP prp;
    mbedtls::ctr_drbg ctr_drbg;

    std::array<uint8_t, mbedtls::aes_gcm_256::KEY_BYTES> key;
    ctr_drbg.fill(key);
    mbedtls::aes_gcm_256 cipher(key);

    auto result = json::array();
    for (size_t i = 0; i < UINT16_MAX; i++)
    {
        result.emplace_back(test(prp, cipher, ctr_drbg));
    }

    std::ofstream of("perf_primitive.json");
    of << result.dump() << std::endl;
    of.close();
}
