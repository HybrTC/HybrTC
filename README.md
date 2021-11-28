# HybrTC

Mail us at hybrtc@googlegroups.com if you have any query.

## Development Dependencies

- [Operating System] Ubuntu 20.04.3 LTS
- [Compiler] clang-10
- [Compiler] clang++-10
- [SDK] [Open Enclave SDK](https://github.com/openenclave/openenclave)
    - v0.17.2
    - lvi-mitigation disabled
- [Library] [Mbed TLS](https://github.com/ARMmbed/mbedtls)
    - v2.27.0
- [Library] [Protocol Buffers](https://github.com/protocolbuffers/protobuf)
    - v3.18.1

## Build and Run

Clone the repository with `--recursive`

``` shell
$ mkdir build && cd build
$ cmake ..
$ make -j
$ make rundemo
```

The default behaviour is to run all the tests once.
You may configure to rule out some cases by editing these lines.

``` cmake
set(PSI_DATA_SET_SIZE_LOG 10;12;14;16;18;20)

set(PSI_SELECT_POLICY ${PSI_SELECT_ALL_PASSTHROUGH} ${PSI_SELECT_ALL_OBLIVIOUS}
                      ${PSI_SELECT_ODD_OBLIVIOUS})

set(PSI_AGGREGATE_POLICY ${PSI_AGGREAGATE_SELECT} ${PSI_AGGREAGATE_JOIN_COUNT}
                         ${PSI_AGGREAGATE_JOIN_SUM})
```

## Develoment tools

- clang-format-10
- clang-tidy-10
- clangd-13
- cmake 3.22.0
- cmake-format
