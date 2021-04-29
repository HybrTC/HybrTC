#include <stdio.h>

#include "helloworld_t.h"

void enclave_helloworld()
{
    fprintf(stdout, "Hello world from the enclave\n");
}
