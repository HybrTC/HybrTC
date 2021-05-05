#pragma once

#include <cstddef>
#include <type_traits>

#include "common/types.hpp"
#include "internal/resource.hpp"

namespace mbedtls
{
#include <mbedtls/sha512.h>

class sha512 : public internal::resource<
                   mbedtls_sha512_context,
                   mbedtls_sha512_init,
                   mbedtls_sha512_free>
{
    constexpr static size_t hash_size = 512 >> 3;

  public:
    sha512()
    {
        mbedtls_sha512_starts_ret(get(), 0);
    }

    template <class U, typename = std::enable_if_t<std::is_integral<U>::value>>
    void update(U value)
    {
        mbedtls_sha512_update_ret(get(), u8p(&value), sizeof(U));
    }

    template <size_t N>
    void update(const a8<N>& input)
    {
        mbedtls_sha512_update_ret(get(), input.data(), input.size());
    }

    void update(const v8& input)
    {
        mbedtls_sha512_update_ret(get(), input.data(), input.size());
    }

    void update(const uint8_t* input, size_t size)
    {
        mbedtls_sha512_update_ret(get(), input, size);
    }

    auto finish() -> a8<hash_size>
    {
        a8<hash_size> h;
        mbedtls_sha512_finish_ret(get(), &h[0]);
        return h;
    }
};

} // namespace mbedtls
