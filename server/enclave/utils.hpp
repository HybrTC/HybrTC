#pragma once

#include <openenclave/enclave.h>
#include <nlohmann/json.hpp>

#include "common/types.hpp"
#include "crypto/ctr_drbg.hpp"
#include "crypto/gcm.hpp"

static void dump(const v8& bytes, uint8_t** obuf, size_t* olen)
{
    *olen = bytes.size();
    *obuf = u8p(oe_host_malloc(bytes.size()));
    memcpy(*obuf, bytes.data(), bytes.size());
}

static void dump_enc(
    const v8& bytes,
    mbedtls::aes_gcm_256& aes,
    mbedtls::ctr_drbg& ctr_drbg,
    uint8_t** obuf,
    size_t* olen)
{
    dump(aes.encrypt(bytes, ctr_drbg), obuf, olen);
}
