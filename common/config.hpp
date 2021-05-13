#pragma once

#ifndef PSI_PAILLIER_PK_LEN
#define PSI_PAILLIER_PK_LEN 128
#endif

#ifndef PSI_DATA_SET_SIZE_LOG
#define PSI_DATA_SET_SIZE_LOG 12
#endif

#define PSI_DATA_KEY_RANGE_LOG (PSI_DATA_SET_SIZE_LOG) * 3 / 2

/* define select policy */
#ifndef PSI_SELECT_ODD
#ifndef PSI_SELECT_EVEN
#define PSI_SELECT_ALL
#endif
#endif

#define PSI_SELECT_ONLY

/* define aggregate policy */
#ifndef PSI_SELECT_ONLY
#ifndef PSI_JOIN_COUNT
#define PSI_JOIN_SUM
#endif
#endif

/* define melbourne shuffle parameter */
#ifndef PSI_MELBOURNE_P
#define PSI_MELBOURNE_P 3
#endif
