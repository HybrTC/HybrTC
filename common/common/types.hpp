#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <vector>

using u8 = std::uint8_t;
using u32 = std::uint32_t;
using u64 = std::uint64_t;

template <class T>
auto u8p(T* ptr) -> u8*
{
    return reinterpret_cast<u8*>(ptr);
}

template <class T>
auto u8p(const T* ptr) -> const u8*
{
    return reinterpret_cast<const u8*>(ptr);
}

template <size_t N>
using a8 = std::array<u8, N>;

using v8 = std::vector<u8>;
using v32 = std::vector<u32>;

template <class T>
using sptr = std::shared_ptr<T>;
