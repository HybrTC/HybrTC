#pragma once

#include "internal/resource.hpp"

namespace mbedtls
{
#include <mbedtls/ecp.h>

class ecp_keypair : public internal::resource<mbedtls_ecp_keypair, mbedtls_ecp_keypair_init, mbedtls_ecp_keypair_free>
{
};

} // namespace mbedtls
