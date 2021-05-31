# HybrTC

Mail us at hybrtc@googlegroups.com if you have any query.

## Development Dependencies

- [Operating System] Ubuntu 18.04.5 LTS
- [Compiler] clang-8
- [Compiler] clang++-8
- [SDK] [Open Enclave SDK](https://github.com/openenclave/openenclave)
    - v0.15.0
    - lvi-mitigation disabled
- [Library] [Mbed TLS](https://github.com/ARMmbed/mbedtls)
    - v2.25.0

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
- clangd-12
- cmake 3.18.4
- cmake-format
