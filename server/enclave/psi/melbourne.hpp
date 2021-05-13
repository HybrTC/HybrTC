#pragma once

#include <utility>

#include "common/types.hpp"

using database_t = std::vector<std::pair<u32, u32>>;

auto melbourne_shuffle(const u32* keys, const u32* vals, size_t size)
    -> database_t;
