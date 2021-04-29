#include <stddef.h>
#include <array>
#include <cstdint>
#include <cstdio>
#include <vector>

#include "helloworld_t.h"

void enclave_helloworld(const uint32_t* data, size_t length)
{
    for (size_t i = 0; i < length; i++)
    {
        printf(
            "%d %08x\n",
            oe_is_outside_enclave(data + i, sizeof(uint32_t)),
            data[i]);
    }
    puts("");
}
