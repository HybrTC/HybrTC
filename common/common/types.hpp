#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <vector>

template <class T>
auto u8p(T* ptr) -> uint8_t*
{
    return reinterpret_cast<uint8_t*>(ptr);
}

template <class T>
auto u8p(const T* ptr) -> const uint8_t*
{
    return reinterpret_cast<const uint8_t*>(ptr);
}

template <size_t N>
using a8 = std::array<uint8_t, N>;

using v8 = std::vector<uint8_t>;
using v32 = std::vector<uint32_t>;