#pragma once

#include "internal/resource.hpp"

namespace mbedtls
{
#include <mbedtls/entropy.h>

class entropy : public internal::resource<mbedtls_entropy_context, &mbedtls_entropy_init, &mbedtls_entropy_free>
{
};

} // namespace mbedtls
