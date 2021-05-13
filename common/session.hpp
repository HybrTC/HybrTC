#pragma once

#include <cstdint>
#include "common/types.hpp"
#include "crypto/ctr_drbg.hpp"
#include "crypto/gcm.hpp"
#include "crypto/sha256.hpp"
#include "log.h"

extern std::shared_ptr<mbedtls::ctr_drbg> ctr_drbg;

namespace PSI
{
using mbedtls::aes_gcm_256;
using mbedtls::hash256;

class Session
{
    using key_t = hash256;
    key_t session_key;

  public:
    Session(const key_t& key) : session_key(key)
    {
    }

    auto encrypt(const v8& input) -> v8
    {
        return encrypt(input.data(), input.size());
    }

    auto encrypt(const std::vector<uint32_t>& input) -> v8
    {
        return encrypt(u8p(input.data()), input.size() * sizeof(uint32_t));
    }

    auto encrypt(const uint8_t* input, size_t input_size) -> v8
    {
        auto crypto = aes_gcm_256(session_key);
        return crypto.encrypt(input, input_size, *ctr_drbg);
    }

    [[nodiscard]] auto decrypt(const v8& input) -> v8
    {
        return decrypt(input.data(), input.size());
    }

    auto decrypt(const uint8_t* input, size_t input_size) -> v8
    {
        auto crypto = aes_gcm_256(session_key);
        return crypto.decrypt(input, input_size);
    }
};

}; // namespace PSI
