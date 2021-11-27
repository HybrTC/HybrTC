#pragma once

#include "common/types.hpp"
#include "crypto/gcm.hpp"
#include "crypto/sha256.hpp"
#include "sgx/log.h"

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

    Session(const Session& o) = delete;

    auto cipher() -> aes_gcm_256
    {
        return aes_gcm_256(session_key);
    }
};

}; // namespace PSI
