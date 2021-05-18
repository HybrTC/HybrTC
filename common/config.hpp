#pragma once

/*
 * define logging option
 */

#ifdef VERBOSE
#define PSI_ENABLE_TRACE_ENCLAVE
#define SPDLOG_ACTIVE_LEVEL SPDLOG_LEVEL_DEBUG
#else
#define SPDLOG_ACTIVE_LEVEL SPDLOG_LEVEL_INFO
#endif

/*
 * define the size of date set
 */

#ifndef PSI_DATA_SET_SIZE_LOG
#define PSI_DATA_SET_SIZE_LOG 12
#endif

#define PSI_DATA_KEY_RANGE_LOG (PSI_DATA_SET_SIZE_LOG) * 3 / 2

/*
 * define the bitlen of paillier public key
 */

#ifndef PSI_PAILLIER_PK_LEN
#define PSI_PAILLIER_PK_LEN 128
#endif

/*
 * define select policy
 */

#define PSI_SELECT_ALL_PASSTHROUGH 0x00
#define PSI_SELECT_ALL_OBLIVIOUS   0x10
#define PSI_SELECT_ODD_OBLIVIOUS   0x11

#ifdef PSI_DISABLE_SHUFFLE

#if PSI_SELECT_POLICY != PSI_SELECT_ALL_PASSTHROUGH
#error "only PSI_SELECT_ALL_PASSTHROUGH is allowed when melbourne shuffle is disabled"
#endif

#ifndef PSI_SELECT_POLICY
#define PSI_SELECT_POLICY PSI_SELECT_ALL_PASSTHROUGH
#endif // PSI_SELECT_POLICY

#else

#ifndef PSI_SELECT_POLICY
#define PSI_SELECT_POLICY PSI_SELECT_ALL_OBLIVIOUS
#endif // PSI_SELECT_POLICY

/* define melbourne shuffle parameter */
#ifndef PSI_MELBOURNE_P
#define PSI_MELBOURNE_P 3
#endif // PSI_MELBOURNE_P

#endif // PSI_DISABLE_SHUFFLE

/*
 * define aggregate policy
 */

#define PSI_AGGREAGATE_SELECT     0x00
#define PSI_AGGREAGATE_JOIN_COUNT 0x10
#define PSI_AGGREAGATE_JOIN_SUM   0x11

#ifndef PSI_AGGREGATE_POLICY
#define PSI_AGGREGATE_POLICY PSI_AGGREAGATE_JOIN_COUNT
#endif // PSI_AGGREGATE_POLICY
