#pragma once

#include <cstdint>

struct record
{
    uint64_t key;
    uint32_t value;
    uint32_t tag;
};
