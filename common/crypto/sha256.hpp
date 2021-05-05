#pragma once

#include <type_traits>

#include "common/types.hpp"
#include "internal/resource.hpp"

namespace mbedtls
{
#include <mbedtls/sha256.h>

class sha256 : public internal::resource<
                   mbedtls_sha256_context,
                   mbedtls_sha256_init,
                   mbedtls_sha256_free>
{
    constexpr static size_t hash_size = 256 >> 3;

  public:
    sha256()
    {
        mbedtls_sha256_starts_ret(get(), 0);
    }

    template <class U, typename = std::enable_if_t<std::is_integral<U>::value>>
    void update(U value)
    {
        mbedtls_sha256_update_ret(get(), u8p(&value), sizeof(U));
    }

    void update(const v8& input)
    {
        mbedtls_sha256_update_ret(get(), input.data(), input.size());
    }

    void update(const uint8_t* input, size_t size)
    {
        mbedtls_sha256_update_ret(get(), input, size);
    }

    auto finish() -> a8<hash_size>
    {
        a8<hash_size> h;
        mbedtls_sha256_finish_ret(get(), &h[0]);
        return h;
    }
};

} // namespace mbedtls
