// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef OE_SAMPLES_ATTESTATION_COMMON_LOG_H
#define OE_SAMPLES_ATTESTATION_COMMON_LOG_H

#include <cstddef>
#include <cstdio>
#include <sstream>
#include <string>
#include <thread>

#include "config.hpp"

static auto get_thread_id() -> std::string
{
    std::stringstream s;
    s << std::hex << std::this_thread::get_id();
    return s.str();
}

template <class T>
static auto hexdump(const T& data) -> std::string
{
    std::string h;
    char buf[BUFSIZ];
    for (auto b : data)
    {
        snprintf(buf, BUFSIZ, "%02hhx", b);
        h += buf;
    }
    return h;
}

template <class T>
static auto hexdump(const T* data, size_t sz) -> std::string
{
    std::string h;
    char buf[BUFSIZ];
    for (size_t i = 0; i < sz; i++)
    {
        snprintf(buf, BUFSIZ, "%02hhx", data[i]);
        h += buf;
    }
    return h;
}

#ifdef PSI_ENABLE_TRACE_ENCLAVE

#define TRACE_ENCLAVE(fmt, ...)       \
    fprintf(                          \
        stderr,                       \
        ">>> [%s] %s(%d): " fmt "\n", \
        get_thread_id().c_str(),      \
        __FILE__,                     \
        __LINE__,                     \
        ##__VA_ARGS__)

#else

#define TRACE_ENCLAVE(fmt, ...) (void)(fmt)

#endif

#endif // OE_SAMPLES_ATTESTATION_COMMON_LOG_H
