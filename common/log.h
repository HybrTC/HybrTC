// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef OE_SAMPLES_ATTESTATION_COMMON_LOG_H
#define OE_SAMPLES_ATTESTATION_COMMON_LOG_H

#include <cstdio>

#define TRACE_ENCLAVE(fmt, ...) \
    fprintf(stderr, ">>> %s(%d): " fmt "\n", __FILE__, __LINE__, ##__VA_ARGS__)

#endif // OE_SAMPLES_ATTESTATION_COMMON_LOG_H
