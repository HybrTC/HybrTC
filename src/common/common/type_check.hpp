#pragma once

#include <type_traits>

#define INTEGER_CHECK(t, msg) static_assert(std::is_integral<t>::value, msg " must be an integer")
