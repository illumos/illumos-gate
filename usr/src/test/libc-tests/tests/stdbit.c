/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2025 Oxide Computer Company
 */

/*
 * Test various aspects of the libc stdbit(3HEAD) interfaces. This does not test
 * the generic interfaces so that way this can be built and run by compilers
 * that don't support C23 and we also want to explicitly test the various type
 * specific values.
 *
 * This test is built 32-bit and 64-bit. The width of a long varies between an
 * ILP32 and LP64 environment and therefore will end up getting back different
 * values. Hence the ifdefs.
 */

#include <stdbit.h>
#include <stdlib.h>
#include <stdio.h>
#include <err.h>
#include <sys/debug.h>
#include <sys/sysmacros.h>

typedef enum {
	STDBIT_TEST_U8	 = 1 << 0,
	STDBIT_TEST_U16	 = 1 << 1,
	STDBIT_TEST_U32	 = 1 << 2,
	STDBIT_TEST_U64	 = 1 << 3
} stdbit_test_type_t;

#define	STDBIT_TEST_64P	(STDBIT_TEST_U64)
#define	STDBIT_TEST_32P	(STDBIT_TEST_U32  | STDBIT_TEST_64P)
#define	STDBIT_TEST_16P	(STDBIT_TEST_U16 | STDBIT_TEST_32P)
#define	STDBIT_TEST_ALL	(STDBIT_TEST_U8 | STDBIT_TEST_16P)

typedef struct {
	const char *so_name;
	unsigned int (*so_uc)(unsigned char);
	unsigned int (*so_us)(unsigned short);
	unsigned int (*so_ui)(unsigned int);
	unsigned int (*so_ul)(unsigned long);
	unsigned int (*so_ull)(unsigned long long);
	int32_t so_delta[3];
} stdbit_ops_t;

typedef struct {
	stdbit_test_type_t st_types;
	uint64_t st_val;
	uint64_t st_res;
} stdbit_test_t;

/*
 * Count Leading Zeros tests. As the integer increases in size, there are a
 * bunch of leading zeros added, hence the delta values in this entry.
 */
static const stdbit_ops_t stdbit_clz_ops = {
	.so_name = "Count Leading Zeros",
	.so_uc = stdc_leading_zeros_uc,
	.so_us = stdc_leading_zeros_us,
	.so_ui = stdc_leading_zeros_ui,
	.so_ul = stdc_leading_zeros_ul,
	.so_ull = stdc_leading_zeros_ull,
	.so_delta = { 8, 16, 32 }
};

static const stdbit_test_t stdbit_clz_tests[] = { {
	.st_types = STDBIT_TEST_ALL,
	.st_val = 0,
	.st_res = 8
}, {
	.st_types = STDBIT_TEST_ALL,
	.st_val = UINT8_MAX,
	.st_res = 0
}, {
	.st_types = STDBIT_TEST_ALL,
	.st_val = 0x42,
	.st_res = 1
}, {
	.st_types = STDBIT_TEST_ALL,
	.st_val = 1,
	.st_res = 7
}, {
	.st_types = STDBIT_TEST_16P,
	.st_val = UINT16_MAX,
	.st_res = 0
}, {
	.st_types = STDBIT_TEST_16P,
	.st_val = 0x7777,
	.st_res = 1
}, {
	.st_types = STDBIT_TEST_16P,
	.st_val = 0x800,
	.st_res = 4
}, {
	.st_types = STDBIT_TEST_16P,
	.st_val = 0x080,
	.st_res = 8
}, {
	.st_types = STDBIT_TEST_16P,
	.st_val = 0x008,
	.st_res = 12
}, {
	.st_types = STDBIT_TEST_32P,
	.st_val = UINT32_MAX,
	.st_res = 0
}, {
	.st_types = STDBIT_TEST_32P,
	.st_val = 0x23000000,
	.st_res = 2
}, {
	.st_types = STDBIT_TEST_32P,
	.st_val = 0x23000032,
	.st_res = 2
}, {
	.st_types = STDBIT_TEST_64P,
	.st_val = 0x400000000,
	.st_res = 29
}, {
	.st_types = STDBIT_TEST_64P,
	.st_val = UINT64_MAX,
	.st_res = 0
} };

/*
 * Unlike count leading zeros, when we take a value and hand it to a larger
 * function, it will always go to a value of zero. As a result, we don't test
 * many of this suite across everything.
 */
static const stdbit_ops_t stdbit_clo_ops = {
	.so_name = "Count Leading Ones",
	.so_uc = stdc_leading_ones_uc,
	.so_us = stdc_leading_ones_us,
	.so_ui = stdc_leading_ones_ui,
	.so_ul = stdc_leading_ones_ul,
	.so_ull = stdc_leading_ones_ull,
};


static const stdbit_test_t stdbit_clo_tests[] = { {
	.st_types = STDBIT_TEST_U8,
	.st_val = UINT8_MAX,
	.st_res = 8
}, {
	.st_types = STDBIT_TEST_ALL,
	.st_val = 0,
	.st_res = 0
}, {
	.st_types = STDBIT_TEST_ALL,
	.st_val = 0x42,
	.st_res = 0
}, {
	.st_types = STDBIT_TEST_U8,
	.st_val = 0xe0,
	.st_res = 3
}, {
	.st_types = STDBIT_TEST_U8,
	.st_val = 0xfc,
	.st_res = 6
}, {
	.st_types = STDBIT_TEST_16P,
	.st_val = UINT8_MAX,
	.st_res = 0
}, {
	.st_types = STDBIT_TEST_16P,
	.st_val = 0x142,
	.st_res = 0
}, {
	.st_types = STDBIT_TEST_U16,
	.st_val = UINT16_MAX,
	.st_res = 16
}, {
	.st_types = STDBIT_TEST_U16,
	.st_val = 0xc0ff,
	.st_res = 2
}, {
	.st_types = STDBIT_TEST_U16,
	.st_val = 0xf88f,
	.st_res = 5
}, {
	.st_types = STDBIT_TEST_U32,
	.st_val = 0x12345678,
	.st_res = 0
}, {
	.st_types = STDBIT_TEST_U32,
	.st_val = UINT32_MAX,
	.st_res = 32
}, {
	.st_types = STDBIT_TEST_U32,
	.st_val = 0x87654321,
	.st_res = 1
}, {
	.st_types = STDBIT_TEST_U32,
	.st_val = 0xff7ff7ff,
	.st_res = 8
}, {
	.st_types = STDBIT_TEST_U32,
	.st_val = 0xfffffeee,
	.st_res = 23
}, {
	.st_types = STDBIT_TEST_U64,
	.st_val = UINT64_MAX,
	.st_res = 64
}, {
	.st_types = STDBIT_TEST_U64,
	.st_val = 0x8000000000000000,
	.st_res = 1
}, {
	.st_types = STDBIT_TEST_U64,
	.st_val = 0xffffffff80000000,
	.st_res = 33
}, {
	.st_types = STDBIT_TEST_U64,
	.st_val = 0xffffffffffff9999,
	.st_res = 49
} };

/*
 * The results for zero is the only special case that occurs with this
 * particular case.
 */
static const stdbit_ops_t stdbit_ctz_ops = {
	.so_name = "Count Trailing Zeros",
	.so_uc = stdc_trailing_zeros_uc,
	.so_us = stdc_trailing_zeros_us,
	.so_ui = stdc_trailing_zeros_ui,
	.so_ul = stdc_trailing_zeros_ul,
	.so_ull = stdc_trailing_zeros_ull,
};

static const stdbit_test_t stdbit_ctz_tests[] = { {
	.st_types = STDBIT_TEST_U8,
	.st_val = 0,
	.st_res = 8
}, {
	.st_types = STDBIT_TEST_U16,
	.st_val = 0,
	.st_res = 16
}, {
	.st_types = STDBIT_TEST_U32,
	.st_val = 0,
	.st_res = 32
}, {
	.st_types = STDBIT_TEST_U64,
	.st_val = 0,
	.st_res = 64
}, {
	.st_types = STDBIT_TEST_ALL,
	.st_val = UINT8_MAX,
	.st_res = 0
}, {
	.st_types = STDBIT_TEST_ALL,
	.st_val = 0x1,
	.st_res = 0
}, {
	.st_types = STDBIT_TEST_ALL,
	.st_val = 0x4,
	.st_res = 2
}, {
	.st_types = STDBIT_TEST_ALL,
	.st_val = 0x80,
	.st_res = 7
}, {
	.st_types = STDBIT_TEST_16P,
	.st_val = 0xff60,
	.st_res = 5
}, {
	.st_types = STDBIT_TEST_16P,
	.st_val = 0x8ad0,
	.st_res = 4
}, {
	.st_types = STDBIT_TEST_16P,
	.st_val = 0x2300,
	.st_res = 8
}, {
	.st_types = STDBIT_TEST_32P,
	.st_val = 0x42000000,
	.st_res = 25
}, {
	.st_types = STDBIT_TEST_32P,
	.st_val = 0x99887700,
	.st_res = 8
}, {
	.st_types = STDBIT_TEST_32P,
	.st_val = UINT32_MAX,
	.st_res = 0
}, {
	.st_types = STDBIT_TEST_64P,
	.st_val = 0xaa00000000000000,
	.st_res = 57
}, {
	.st_types = STDBIT_TEST_64P,
	.st_val = 0xbadcaf0000000000,
	.st_res = 40
}, {
	.st_types = STDBIT_TEST_64P,
	.st_val = UINT64_MAX,
	.st_res = 0
} };

/*
 * Count Trailing Ones Tests
 */
static const stdbit_ops_t stdbit_cto_ops = {
	.so_name = "Count Trailing Ones",
	.so_uc = stdc_trailing_ones_uc,
	.so_us = stdc_trailing_ones_us,
	.so_ui = stdc_trailing_ones_ui,
	.so_ul = stdc_trailing_ones_ul,
	.so_ull = stdc_trailing_ones_ull,
};

static const stdbit_test_t stdbit_cto_tests[] = { {
	.st_types = STDBIT_TEST_ALL,
	.st_val = UINT8_MAX,
	.st_res = 8
}, {
	.st_types = STDBIT_TEST_ALL,
	.st_val = 0,
	.st_res = 0
}, {
	.st_types = STDBIT_TEST_ALL,
	.st_val = 3,
	.st_res = 2
}, {
	.st_types = STDBIT_TEST_ALL,
	.st_val = 0x7e,
	.st_res = 0
}, {
	.st_types = STDBIT_TEST_ALL,
	.st_val = 0x7f,
	.st_res = 7
}, {
	.st_types = STDBIT_TEST_16P,
	.st_val = UINT16_MAX,
	.st_res = 16
}, {
	.st_types = STDBIT_TEST_16P,
	.st_val = 0x8765,
	.st_res = 1
}, {
	.st_types = STDBIT_TEST_16P,
	.st_val = 0xcdef,
	.st_res = 4
}, {
	.st_types = STDBIT_TEST_16P,
	.st_val = 0x9fff,
	.st_res = 13
}, {
	.st_types = STDBIT_TEST_32P,
	.st_val = UINT32_MAX,
	.st_res = 32
}, {
	.st_types = STDBIT_TEST_32P,
	.st_val = 0x85ab91ff,
	.st_res = 9
}, {
	.st_types = STDBIT_TEST_32P,
	.st_val = 0x7fffffff,
	.st_res = 31
}, {
	.st_types = STDBIT_TEST_64P,
	.st_val = UINT64_MAX,
	.st_res = 64
}, {
	.st_types = STDBIT_TEST_64P,
	.st_val = 0x1bffffffffffffff,
	.st_res = 58
}, {
	.st_types = STDBIT_TEST_64P,
	.st_val = 0x9abe83cff6ff7ff8,
	.st_res = 0
} };

/*
 * See the manual. The C23 definition for "most-significant" bit is
 * counter-intuitive. Basically bit 0 is considered the most significant bit. So
 * for a uint8_t bit 0 is considered index 7 and bit 7 is index 0. The results
 * always have 1 added to them.
 */
static const stdbit_ops_t stdbit_flz_ops = {
	.so_name = "First Leading Zero",
	.so_uc = stdc_first_leading_zero_uc,
	.so_us = stdc_first_leading_zero_us,
	.so_ui = stdc_first_leading_zero_ui,
	.so_ul = stdc_first_leading_zero_ul,
	.so_ull = stdc_first_leading_zero_ull,
};

static const stdbit_test_t stdbit_flz_tests[] = { {
	.st_types = STDBIT_TEST_ALL,
	.st_val = 0,
	.st_res = 1
}, {
	.st_types = STDBIT_TEST_ALL,
	.st_val = 0x3,
	.st_res = 1
}, {
	.st_types = STDBIT_TEST_U8,
	.st_val = 0xf0,
	.st_res = 5
}, {
	.st_types = STDBIT_TEST_U8,
	.st_val = 0xef,
	.st_res = 4
}, {
	.st_types = STDBIT_TEST_U8,
	.st_val = 0xc4,
	.st_res = 3
}, {
	.st_types = STDBIT_TEST_U8,
	.st_val = UINT8_MAX,
	.st_res = 0
}, {
	.st_types = STDBIT_TEST_16P,
	.st_val = UINT8_MAX,
	.st_res = 1
}, {
	.st_types = STDBIT_TEST_U16,
	.st_val = UINT16_MAX,
	.st_res = 0
}, {
	.st_types = STDBIT_TEST_U16,
	.st_val = 0xfabc,
	.st_res = 6
}, {
	.st_types = STDBIT_TEST_U16,
	.st_val = 0xcbaf,
	.st_res = 3
}, {
	.st_types = STDBIT_TEST_32P,
	.st_val = UINT16_MAX,
	.st_res = 1
}, {
	.st_types = STDBIT_TEST_U32,
	.st_val = UINT32_MAX,
	.st_res = 0
}, {
	.st_types = STDBIT_TEST_U32,
	.st_val = 0xff7ff623,
	.st_res = 9
}, {
	.st_types = STDBIT_TEST_U32,
	.st_val = 0xfffff623,
	.st_res = 21
}, {
.	st_types = STDBIT_TEST_U32,
	.st_val = 0xffffff95,
	.st_res = 26
}, {
	.st_types = STDBIT_TEST_64P,
	.st_val = UINT32_MAX,
	.st_res = 1
}, {
	.st_types = STDBIT_TEST_U64,
	.st_val = UINT64_MAX,
	.st_res = 0
}, {
	.st_types = STDBIT_TEST_U64,
	.st_val = 0xfffffffffffffffe,
	.st_res = 64
}, {
	.st_types = STDBIT_TEST_U64,
	.st_val = 0xffff2b9542fffffe,
	.st_res = 17
} };

/*
 * See the note on the flz tests for the oddities with calculating this. Due to
 * the nature of how these are counted, the larger the number gets, the more the
 * first 1 increases in its "most-significant" value. However, we have to
 * special case 0 in our logic because it will stay consistent across all the
 * values.
 */
static const stdbit_ops_t stdbit_flo_ops = {
	.so_name = "First Leading One",
	.so_uc = stdc_first_leading_one_uc,
	.so_us = stdc_first_leading_one_us,
	.so_ui = stdc_first_leading_one_ui,
	.so_ul = stdc_first_leading_one_ul,
	.so_ull = stdc_first_leading_one_ull,
	.so_delta = { 8, 16, 32 }
};

static const stdbit_test_t stdbit_flo_tests[] = { {
	.st_types = STDBIT_TEST_U8,
	.st_val = 0,
	.st_res = 0
}, {
	.st_types = STDBIT_TEST_U16,
	.st_val = 0,
	.st_res = 0
}, {
	.st_types = STDBIT_TEST_U32,
	.st_val = 0,
	.st_res = 0
}, {
	.st_types = STDBIT_TEST_U64,
	.st_val = 0,
	.st_res = 0
}, {
	.st_types = STDBIT_TEST_ALL,
	.st_val = 0x1,
	.st_res = 8
}, {
	.st_types = STDBIT_TEST_ALL,
	.st_val = 0xf,
	.st_res = 5
}, {
	.st_types = STDBIT_TEST_ALL,
	.st_val = 0xfe,
	.st_res = 1
}, {
	.st_types = STDBIT_TEST_ALL,
	.st_val = 0x7f,
	.st_res = 2
}, {
	.st_types = STDBIT_TEST_ALL,
	.st_val = UINT8_MAX,
	.st_res = 1
}, {
	.st_types = STDBIT_TEST_16P,
	.st_val = UINT16_MAX,
	.st_res = 1
}, {
	.st_types = STDBIT_TEST_16P,
	.st_val = 0xfeed,
	.st_res = 1
}, {
	.st_types = STDBIT_TEST_16P,
	.st_val = 0x1aff,
	.st_res = 4
}, {
	.st_types = STDBIT_TEST_16P,
	.st_val = 0x02b0,
	.st_res = 7
}, {
	.st_types = STDBIT_TEST_32P,
	.st_val = UINT32_MAX,
	.st_res = 1
}, {
	.st_types = STDBIT_TEST_32P,
	.st_val = 0x00001234,
	.st_res = 20
}, {
	.st_types = STDBIT_TEST_32P,
	.st_val = 0x2bb22bb2,
	.st_res = 3
}, {
	.st_types = STDBIT_TEST_32P,
	.st_val = 0x00420000,
	.st_res = 10
}, {
	.st_types = STDBIT_TEST_64P,
	.st_val = UINT64_MAX,
	.st_res = 1
}, {
	.st_types = STDBIT_TEST_64P,
	.st_val = 0x000000000c000000,
	.st_res = 37
}, {
	.st_types = STDBIT_TEST_64P,
	.st_val = 0x000fedcba9abcdef,
	.st_res = 13
}, {
	.st_types = STDBIT_TEST_64P,
	.st_val = 0x000001992aa3bb4c,
	.st_res = 24
}, {
	.st_types = STDBIT_TEST_64P,
	.st_val = 0x0706050403020100,
	.st_res = 6
} };

/*
 * First Trailing Zero. This numbers indexes in the way that someone expects
 * where the bit 0 is least significant index zero, which returns a value of 1.
 * When there are no zeros this returns 0. There is no reliable increment
 * pattern here.
 */
static const stdbit_ops_t stdbit_ftz_ops = {
	.so_name = "First Trailing Zero",
	.so_uc = stdc_first_trailing_zero_uc,
	.so_us = stdc_first_trailing_zero_us,
	.so_ui = stdc_first_trailing_zero_ui,
	.so_ul = stdc_first_trailing_zero_ul,
	.so_ull = stdc_first_trailing_zero_ull,
};

static const stdbit_test_t stdbit_ftz_tests[] = { {
	.st_types = STDBIT_TEST_ALL,
	.st_val = 0,
	.st_res = 1
}, {
	.st_types = STDBIT_TEST_U8,
	.st_val = UINT8_MAX,
	.st_res = 0
}, {
	.st_types = STDBIT_TEST_U8,
	.st_val = 0xfe,
	.st_res = 1
}, {
	.st_types = STDBIT_TEST_U8,
	.st_val = 0xef,
	.st_res = 5
}, {
	.st_types = STDBIT_TEST_U8,
	.st_val = 0x7f,
	.st_res = 8
}, {
	.st_types = STDBIT_TEST_U16,
	.st_val = UINT8_MAX,
	.st_res = 9
}, {
	.st_types = STDBIT_TEST_U16,
	.st_val = UINT16_MAX,
	.st_res = 0
}, {
	.st_types = STDBIT_TEST_U16,
	.st_val = 0xfffe,
	.st_res = 1
}, {
	.st_types = STDBIT_TEST_U16,
	.st_val = 0xefff,
	.st_res = 13
}, {
	.st_types = STDBIT_TEST_U16,
	.st_val = 0x07ff,
	.st_res = 12
}, {
	.st_types = STDBIT_TEST_U32,
	.st_val = UINT16_MAX,
	.st_res = 17
}, {
	.st_types = STDBIT_TEST_U32,
	.st_val = UINT32_MAX,
	.st_res = 0
}, {
	.st_types = STDBIT_TEST_U32,
	.st_val = 0xcaffffff,
	.st_res = 25
}, {
	.st_types = STDBIT_TEST_U32,
	.st_val = 0xcabfffff,
	.st_res = 23
}, {
	.st_types = STDBIT_TEST_U64,
	.st_val = UINT32_MAX,
	.st_res = 33
}, {
	.st_types = STDBIT_TEST_U64,
	.st_val = UINT64_MAX,
	.st_res = 0
}, {
	.st_types = STDBIT_TEST_U64,
	.st_val = 0xface2bface95a2ff,
	.st_res = 9
}, {
	.st_types = STDBIT_TEST_U64,
	.st_val = 0x7777777777777777,
	.st_res = 4
} };

/*
 * First Trailing One. This numbers indexes in the way that someone expects
 * where the bit 0 is least significant index zero, which returns a value of 1.
 * When there are no zeros this returns 0. This is classical ffs().
 */
static const stdbit_ops_t stdbit_fto_ops = {
	.so_name = "First Trailing One",
	.so_uc = stdc_first_trailing_one_uc,
	.so_us = stdc_first_trailing_one_us,
	.so_ui = stdc_first_trailing_one_ui,
	.so_ul = stdc_first_trailing_one_ul,
	.so_ull = stdc_first_trailing_one_ull,
};

static const stdbit_test_t stdbit_fto_tests[] = { {
	.st_types = STDBIT_TEST_ALL,
	.st_val = 0,
	.st_res = 0
}, {
	.st_types = STDBIT_TEST_ALL,
	.st_val = UINT8_MAX,
	.st_res = 1
}, {
	.st_types = STDBIT_TEST_ALL,
	.st_val = 0xf7,
	.st_res = 1
}, {
	.st_types = STDBIT_TEST_ALL,
	.st_val = 0xf8,
	.st_res = 4
}, {
	.st_types = STDBIT_TEST_ALL,
	.st_val = 0x6d,
	.st_res = 1
}, {
	.st_types = STDBIT_TEST_ALL,
	.st_val = 0xd6,
	.st_res = 2
}, {
	.st_types = STDBIT_TEST_ALL,
	.st_val = 0x40,
	.st_res = 7
}, {
	.st_types = STDBIT_TEST_16P,
	.st_val = UINT16_MAX,
	.st_res = 1
}, {
	.st_types = STDBIT_TEST_16P,
	.st_val = 0xf840,
	.st_res = 7
}, {
	.st_types = STDBIT_TEST_16P,
	.st_val = 0x0a00,
	.st_res = 10
}, {
	.st_types = STDBIT_TEST_16P,
	.st_val = 0x8000,
	.st_res = 16
}, {
	.st_types = STDBIT_TEST_32P,
	.st_val = UINT32_MAX,
	.st_res = 1
}, {
	.st_types = STDBIT_TEST_32P,
	.st_val = 0xb0000000,
	.st_res = 29
}, {
	.st_types = STDBIT_TEST_32P,
	.st_val = 0xf9c00000,
	.st_res = 23
}, {
	.st_types = STDBIT_TEST_32P,
	.st_val = 0xfed81500,
	.st_res = 9
}, {
	.st_types = STDBIT_TEST_64P,
	.st_val = UINT64_MAX,
	.st_res = 1
}, {
	.st_types = STDBIT_TEST_64P,
	.st_val = 0xfed80d0000000000,
	.st_res = 41
}, {
	.st_types = STDBIT_TEST_64P,
	.st_val = 0xff70000000000000,
	.st_res = 53
} };

/*
 * Count Zeros.
 */
static const stdbit_ops_t stdbit_cz_ops = {
	.so_name = "Count Zeros",
	.so_uc = stdc_count_zeros_uc,
	.so_us = stdc_count_zeros_us,
	.so_ui = stdc_count_zeros_ui,
	.so_ul = stdc_count_zeros_ul,
	.so_ull = stdc_count_zeros_ull,
	.so_delta = { 8, 16, 32 }
};

static const stdbit_test_t stdbit_cz_tests[] = { {
	.st_types = STDBIT_TEST_ALL,
	.st_val = 0,
	.st_res = 8
}, {
	.st_types = STDBIT_TEST_ALL,
	.st_val = UINT8_MAX,
	.st_res = 0
}, {
	.st_types = STDBIT_TEST_ALL,
	.st_val = 0x77,
	.st_res = 2
}, {
	.st_types = STDBIT_TEST_ALL,
	.st_val = 0x88,
	.st_res = 6
}, {
	.st_types = STDBIT_TEST_ALL,
	.st_val = 0x5,
	.st_res = 6
}, {
	.st_types = STDBIT_TEST_ALL,
	.st_val = 0x1f,
	.st_res = 3
}, {
	.st_types = STDBIT_TEST_16P,
	.st_val = UINT16_MAX,
	.st_res = 0
}, {
	.st_types = STDBIT_TEST_16P,
	.st_val = 0x1234,
	.st_res = 11
}, {
	.st_types = STDBIT_TEST_16P,
	.st_val = 0x4321,
	.st_res = 11
}, {
	.st_types = STDBIT_TEST_16P,
	.st_val = 0x2ba2,
	.st_res = 9
}, {
	.st_types = STDBIT_TEST_32P,
	.st_val = UINT32_MAX,
	.st_res = 0
}, {
	.st_types = STDBIT_TEST_32P,
	.st_val = 0xdeadbeef,
	.st_res = 8
}, {
	.st_types = STDBIT_TEST_32P,
	.st_val = 0x12345678,
	.st_res = 19
}, {
	.st_types = STDBIT_TEST_64P,
	.st_val = UINT64_MAX,
	.st_res = 0
}, {
	.st_types = STDBIT_TEST_64P,
	.st_val = 0xabbabccbcddcdeed,
	.st_res = 22
}, {
	.st_types = STDBIT_TEST_64P,
	.st_val = 0x1221244248848008,
	.st_res = 50
}, {
	.st_types = STDBIT_TEST_64P,
	.st_val = 0xfffffffeefffffff,
	.st_res = 2
} };

/*
 * Count Ones.
 */
static const stdbit_ops_t stdbit_co_ops = {
	.so_name = "Count Ones",
	.so_uc = stdc_count_ones_uc,
	.so_us = stdc_count_ones_us,
	.so_ui = stdc_count_ones_ui,
	.so_ul = stdc_count_ones_ul,
	.so_ull = stdc_count_ones_ull,
};

static const stdbit_test_t stdbit_co_tests[] = { {
	.st_types = STDBIT_TEST_ALL,
	.st_val = 0,
	.st_res = 0
}, {
	.st_types = STDBIT_TEST_ALL,
	.st_val = UINT8_MAX,
	.st_res = 8
}, {
	.st_types = STDBIT_TEST_ALL,
	.st_val = 0x77,
	.st_res = 6
}, {
	.st_types = STDBIT_TEST_ALL,
	.st_val = 0x88,
	.st_res = 2
}, {
	.st_types = STDBIT_TEST_ALL,
	.st_val = 0x5,
	.st_res = 2
}, {
	.st_types = STDBIT_TEST_ALL,
	.st_val = 0x1f,
	.st_res = 5
}, {
	.st_types = STDBIT_TEST_16P,
	.st_val = UINT16_MAX,
	.st_res = 16
}, {
	.st_types = STDBIT_TEST_16P,
	.st_val = 0x1234,
	.st_res = 5
}, {
	.st_types = STDBIT_TEST_16P,
	.st_val = 0x4321,
	.st_res = 5
}, {
	.st_types = STDBIT_TEST_16P,
	.st_val = 0x2ba2,
	.st_res = 7
}, {
	.st_types = STDBIT_TEST_32P,
	.st_val = UINT32_MAX,
	.st_res = 32
}, {
	.st_types = STDBIT_TEST_32P,
	.st_val = 0xdeadbeef,
	.st_res = 24
}, {
	.st_types = STDBIT_TEST_32P,
	.st_val = 0x12345678,
	.st_res = 13
}, {
	.st_types = STDBIT_TEST_64P,
	.st_val = UINT64_MAX,
	.st_res = 64
}, {
	.st_types = STDBIT_TEST_64P,
	.st_val = 0xabbabccbcddcdeed,
	.st_res = 42
}, {
	.st_types = STDBIT_TEST_64P,
	.st_val = 0x1221244248848008,
	.st_res = 14
}, {
	.st_types = STDBIT_TEST_64P,
	.st_val = 0xfffffffeefffffff,
	.st_res = 62
} };

/*
 * Bit width tests. These values should stay the same as we increase integer
 * sizes as values are only adding zeros.
 */
static const stdbit_ops_t stdbit_bw_ops = {
	.so_name = "Bit Width",
	.so_uc = stdc_bit_width_uc,
	.so_us = stdc_bit_width_us,
	.so_ui = stdc_bit_width_ui,
	.so_ul = stdc_bit_width_ul,
	.so_ull = stdc_bit_width_ull,
};

static const stdbit_test_t stdbit_bw_tests[] = { {
	.st_types = STDBIT_TEST_ALL,
	.st_val = 0,
	.st_res = 0
}, {
	.st_types = STDBIT_TEST_ALL,
	.st_val = UINT8_MAX,
	.st_res = 8
}, {
	.st_types = STDBIT_TEST_ALL,
	.st_val = 0x80,
	.st_res = 8
}, {
	.st_types = STDBIT_TEST_ALL,
	.st_val = 0x08,
	.st_res = 4
}, {
	.st_types = STDBIT_TEST_ALL,
	.st_val = 0x17,
	.st_res = 5
}, {
	.st_types = STDBIT_TEST_16P,
	.st_val = UINT16_MAX,
	.st_res = 16
}, {
	.st_types = STDBIT_TEST_16P,
	.st_val = 0x7777,
	.st_res = 15
}, {
	.st_types = STDBIT_TEST_16P,
	.st_val = 0x2bb2,
	.st_res = 14
}, {
	.st_types = STDBIT_TEST_16P,
	.st_val = 0x0230,
	.st_res = 10
}, {
	.st_types = STDBIT_TEST_32P,
	.st_val = UINT32_MAX,
	.st_res = 32
}, {
	.st_types = STDBIT_TEST_32P,
	.st_val = 0xfedc4000,
	.st_res = 32
}, {
	.st_types = STDBIT_TEST_32P,
	.st_val = 0x0004cedf,
	.st_res = 19
}, {
	.st_types = STDBIT_TEST_32P,
	.st_val = 0x001ee100,
	.st_res = 21
}, {
	.st_types = STDBIT_TEST_64P,
	.st_val = 0x8000000000000000,
	.st_res = 64
}, {
	.st_types = STDBIT_TEST_64P,
	.st_val = 0x00ff11ee22dd33cc,
	.st_res = 56
}, {
	.st_types = STDBIT_TEST_64P,
	.st_val = UINT64_MAX,
	.st_res = 64
} };

static void
stdbit_print_pass(stdbit_test_type_t types, uint64_t val, const char *cat)
{
	bool first = true;
	(void) printf("TEST PASSED: %s (0x%" PRIx64 ") [", cat, val);
	if ((types & STDBIT_TEST_U8) != 0) {
		(void) printf("8");
		first = false;
	}

	if ((types & STDBIT_TEST_U16) != 0) {
		(void) printf("%s16", first ? "" : ",");
		first = false;
	}

	if ((types & STDBIT_TEST_U32) != 0) {
		(void) printf("%s32", first ? "" : ",");
		first = false;
	}

	if ((types & STDBIT_TEST_U64) != 0) {
		(void) printf("%s64", first ? "" : ",");
		first = false;
	}

	(void) printf("]\n");
}

static bool
stdbit_test_one(const stdbit_test_t *test, const stdbit_ops_t *ops)
{
	bool ret = true;
	uint64_t comp = test->st_res;

	VERIFY3U(test->st_types, !=, 0);
	if ((test->st_types & STDBIT_TEST_U8) != 0) {
		unsigned res = ops->so_uc(test->st_val);
		if (res != comp) {
			warnx("TEST FAILED: %s (0x%" PRIx64 ") 8-bit (uchar) "
			    "returned 0x%x, expected 0x%" PRIx64,
			    ops->so_name, test->st_val, res, comp);
			ret = false;
		}

		comp += ops->so_delta[0];
	}

	if ((test->st_types & STDBIT_TEST_U16) != 0) {
		unsigned res = ops->so_us(test->st_val);
		if (res != comp) {
			warnx("TEST FAILED: %s (0x%" PRIx64 ") 16-bit (ushort) "
			    "returned 0x%x, expected 0x%" PRIx64,
			    ops->so_name, test->st_val, res, comp);
			ret = false;
		}

		comp += ops->so_delta[1];
	}

	if ((test->st_types & STDBIT_TEST_U32) != 0) {
		unsigned res = ops->so_ui(test->st_val);
		if (res != comp) {
			warnx("TEST FAILED: %s (0x%" PRIx64 ") 32-bit (uint) "
			    "returned 0x%x, expected 0x%" PRIx64,
			    ops->so_name, test->st_val, res, comp);
			ret = false;
		}

#ifdef	_ILP32
		res = ops->so_ul(test->st_val);
		if (res != comp) {
			warnx("TEST FAILED: %s (0x%" PRIx64 ") 32-bit (ulong) "
			    "returned 0x%x, expected 0x%" PRIx64,
			    ops->so_name, test->st_val, res, comp);
			ret = false;
		}
#endif	/* _ILP32 */

		comp += ops->so_delta[2];
	}

	if ((test->st_types & STDBIT_TEST_U64) != 0) {
		unsigned res;
#ifdef	_LP64
		res = ops->so_ul(test->st_val);
		if (res != comp) {
			warnx("TEST FAILED: %s (0x%" PRIx64 ") 64-bit (ulong) "
			    "returned 0x%x, expected 0x%" PRIx64,
			    ops->so_name, test->st_val, res, comp);
			ret = false;
		}
#endif	/* _LP64 */

		res = ops->so_ull(test->st_val);
		if (res != comp) {
			warnx("TEST FAILED: %s (0x%" PRIx64 ") 64-bit (ulong "
			    "long) returned 0x%x, expected 0x%" PRIx64,
			    ops->so_name, test->st_val, res, comp);
			ret = false;
		}
	}

	if (ret) {
		stdbit_print_pass(test->st_types, test->st_val, ops->so_name);
	}

	return (ret);
}

/*
 * This is used for all the functions that can return unsigned.
 */
typedef struct {
	const stdbit_ops_t *sg_ops;
	const stdbit_test_t *sg_tests;
	size_t sg_ntests;
} stdbit_std_group_t;

static const stdbit_std_group_t stdbit_groups[] = {
	{ &stdbit_clz_ops, stdbit_clz_tests, ARRAY_SIZE(stdbit_clz_tests) },
	{ &stdbit_clo_ops, stdbit_clo_tests, ARRAY_SIZE(stdbit_clo_tests) },
	{ &stdbit_ctz_ops, stdbit_ctz_tests, ARRAY_SIZE(stdbit_ctz_tests) },
	{ &stdbit_cto_ops, stdbit_cto_tests, ARRAY_SIZE(stdbit_cto_tests) },
	{ &stdbit_flz_ops, stdbit_flz_tests, ARRAY_SIZE(stdbit_flz_tests) },
	{ &stdbit_flo_ops, stdbit_flo_tests, ARRAY_SIZE(stdbit_flo_tests) },
	{ &stdbit_ftz_ops, stdbit_ftz_tests, ARRAY_SIZE(stdbit_ftz_tests) },
	{ &stdbit_fto_ops, stdbit_fto_tests, ARRAY_SIZE(stdbit_fto_tests) },
	{ &stdbit_cz_ops, stdbit_cz_tests, ARRAY_SIZE(stdbit_cz_tests) },
	{ &stdbit_co_ops, stdbit_co_tests, ARRAY_SIZE(stdbit_co_tests) },
	{ &stdbit_bw_ops, stdbit_bw_tests, ARRAY_SIZE(stdbit_bw_tests) },
};

/*
 * Tests for is a single bit set. These should be the same regardless of integer
 * size.
 */
static const stdbit_test_t stdbit_1b_tests[] = { {
	.st_types = STDBIT_TEST_ALL,
	.st_val = 0,
	.st_res = false
}, {
	.st_types = STDBIT_TEST_ALL,
	.st_val = UINT8_MAX,
	.st_res = false
}, {
	.st_types = STDBIT_TEST_ALL,
	.st_val = 0x40,
	.st_res = true
}, {
	.st_types = STDBIT_TEST_ALL,
	.st_val = 0x23,
	.st_res = false
}, {
	.st_types = STDBIT_TEST_ALL,
	.st_val = 0x81,
	.st_res = false
}, {
	.st_types = STDBIT_TEST_ALL,
	.st_val = 0x08,
	.st_res = true
}, {
	.st_types = STDBIT_TEST_16P,
	.st_val = UINT16_MAX,
	.st_res = false
}, {
	.st_types = STDBIT_TEST_16P,
	.st_val = 0x0100,
	.st_res = true
}, {
	.st_types = STDBIT_TEST_16P,
	.st_val = 0x7777,
	.st_res = false
}, {
	.st_types = STDBIT_TEST_16P,
	.st_val = 0x8000,
	.st_res = true
}, {
	.st_types = STDBIT_TEST_16P,
	.st_val = 0x0400,
	.st_res = true
}, {
	.st_types = STDBIT_TEST_16P,
	.st_val = 0x0020,
	.st_res = true
}, {
	.st_types = STDBIT_TEST_16P,
	.st_val = 0x0001,
	.st_res = true
}, {
	.st_types = STDBIT_TEST_32P,
	.st_val = UINT32_MAX,
	.st_res = false
}, {
	.st_types = STDBIT_TEST_32P,
	.st_val = 0x00200000,
	.st_res = true
}, {
	.st_types = STDBIT_TEST_32P,
	.st_val = 0xbaddcafe,
	.st_res = false
}, {
	.st_types = STDBIT_TEST_32P,
	.st_val = 0x80000000,
	.st_res = true
}, {
	.st_types = STDBIT_TEST_64P,
	.st_val = UINT64_MAX,
	.st_res = false
}, {
	.st_types = STDBIT_TEST_64P,
	.st_val = 0x8000000000000000,
	.st_res = true
}, {
	.st_types = STDBIT_TEST_64P,
	.st_val = 0x0010000000000000,
	.st_res = true
} };

/*
 * The single bit set tests require a slightly different runner because they
 * return a boolean.
 */
static bool
stdbit_1b_test_one(const stdbit_test_t *test)
{
	bool ret = true, comp;

	VERIFY(test->st_res == 0 || test->st_res == 1);
	comp = (bool)test->st_res;

	VERIFY3U(test->st_types, !=, 0);
	if ((test->st_types & STDBIT_TEST_U8) != 0) {
		bool res = stdc_has_single_bit_uc(test->st_val);
		if (res != comp) {
			warnx("TEST FAILED: Single-bit (0x%" PRIx64 ") 8-bit "
			    "(uchar) returned %s, expected %s", test->st_val,
			    res ? "true" : "false", comp ? "true" : "false");
			ret = false;
		}
	}

	if ((test->st_types & STDBIT_TEST_U16) != 0) {
		bool res = stdc_has_single_bit_us(test->st_val);
		if (res != comp) {
			warnx("TEST FAILED: Single-bit (0x%" PRIx64 ") 16-bit "
			    "(ushort) returned %s, expected %s", test->st_val,
			    res ? "true" : "false", comp ? "true" : "false");
			ret = false;
		}
	}

	if ((test->st_types & STDBIT_TEST_U32) != 0) {
		bool res = stdc_has_single_bit_ui(test->st_val);
		if (res != comp) {
			warnx("TEST FAILED: Single-bit (0x%" PRIx64 ") 32-bit "
			    "(uint) returned %s, expected %s", test->st_val,
			    res ? "true" : "false", comp ? "true" : "false");
			ret = false;
		}

#ifdef	_ILP32
		res = stdc_has_single_bit_ul(test->st_val);
		if (res != comp) {
			warnx("TEST FAILED: Single-bit (0x%" PRIx64 ") 32-bit "
			    "(ulong) returned %s, expected %s", test->st_val,
			    res ? "true" : "false", comp ? "true" : "false");
			ret = false;
		}
#endif	/* _ILP32 */
	}

	if ((test->st_types & STDBIT_TEST_U64) != 0) {
		bool res;
#ifdef	_LP64
		res = stdc_has_single_bit_ul(test->st_val);
		if (res != comp) {
			warnx("TEST FAILED: Single-bit (0x%" PRIx64 ") 64-bit "
			    "(ulong) returned %s, expected %s", test->st_val,
			    res ? "true" : "false", comp ? "true" : "false");
			ret = false;
		}
#endif	/* _LP64 */

		res = stdc_has_single_bit_ull(test->st_val);
		if (res != comp) {
			warnx("TEST FAILED: Single-bit (0x%" PRIx64 ") 64-bit "
			    "(ulong long) returned %s, expected %s",
			    test->st_val, res ? "true" : "false",
			    comp ? "true" : "false");
			ret = false;
		}
	}

	if (ret) {
		stdbit_print_pass(test->st_types, test->st_val, "Single-bit");
	}

	return (ret);
}

/*
 * We use a different test structure for the floor and ceiling tests and check
 * both at each stop.
 */
typedef struct {
	stdbit_test_type_t sfc_types;
	uint64_t sfc_val;
	uint64_t sfc_floor;
	uint64_t sfc_ceil;
} stdbit_fc_test_t;

/*
 * Bit floor and ceiling tests. Note, a bit ceiling test can fail and return 0
 * if the value would overlap the type it's in. In those cases we don't use all
 * tests. This happens when the most significant bit in a given integer is set.
 * It will work at the next size up. All others should always pass all tests.
 */
static const stdbit_fc_test_t stdbit_fc_tests[] = { {
	.sfc_types = STDBIT_TEST_ALL,
	.sfc_val = 0,
	.sfc_floor = 0,
	.sfc_ceil = 1
}, {
	.sfc_types = STDBIT_TEST_U8,
	.sfc_val = UINT8_MAX,
	.sfc_floor = 1ULL << 7,
	.sfc_ceil = 0
}, {
	.sfc_types = STDBIT_TEST_ALL,
	.sfc_val = 0x23,
	.sfc_floor = 1ULL << 5,
	.sfc_ceil = 1ULL << 6
}, {
	.sfc_types = STDBIT_TEST_ALL,
	.sfc_val = 0x06,
	.sfc_floor = 1ULL << 2,
	.sfc_ceil = 1ULL << 3
}, {
	.sfc_types = STDBIT_TEST_ALL,
	.sfc_val = 0x18,
	.sfc_floor = 1ULL << 4,
	.sfc_ceil = 1ULL << 5
}, {
	.sfc_types = STDBIT_TEST_U8,
	.sfc_val = 0x81,
	.sfc_floor = 1ULL << 7,
	.sfc_ceil = 0
}, {
	.sfc_types = STDBIT_TEST_16P,
	.sfc_val = UINT8_MAX,
	.sfc_floor = 1ULL << 7,
	.sfc_ceil = 1ULL << 8
}, {
	.sfc_types = STDBIT_TEST_16P,
	.sfc_val = 0x0ff7,
	.sfc_floor = 1ULL << 11,
	.sfc_ceil = 1ULL << 12
}, {
	.sfc_types = STDBIT_TEST_16P,
	.sfc_val = 0x20a4,
	.sfc_floor = 1ULL << 13,
	.sfc_ceil = 1ULL << 14
}, {
	.sfc_types = STDBIT_TEST_U16,
	.sfc_val = 0x8ab1,
	.sfc_floor = 1ULL << 15,
	.sfc_ceil = 0
}, {
	.sfc_types = STDBIT_TEST_U16,
	.sfc_val = UINT16_MAX,
	.sfc_floor = 1ULL << 15,
	.sfc_ceil = 0
}, {
	.sfc_types = STDBIT_TEST_32P,
	.sfc_val = UINT16_MAX,
	.sfc_floor = 1ULL << 15,
	.sfc_ceil = 1ULL << 16
}, {
	.sfc_types = STDBIT_TEST_32P,
	.sfc_val = 0x000271ab,
	.sfc_floor = 1ULL << 17,
	.sfc_ceil = 1ULL << 18
}, {
	.sfc_types = STDBIT_TEST_32P,
	.sfc_val = 0x01000009,
	.sfc_floor = 1ULL << 24,
	.sfc_ceil = 1ULL << 25
}, {
	.sfc_types = STDBIT_TEST_32P,
	.sfc_val = 0x02000000,
	.sfc_floor = 1ULL << 25,
	.sfc_ceil = 1ULL << 25
}, {
	.sfc_types = STDBIT_TEST_32P,
	.sfc_val = 0x1cabf917,
	.sfc_floor = 1ULL << 28,
	.sfc_ceil = 1ULL << 29
}, {
	.sfc_types = STDBIT_TEST_U32,
	.sfc_val = 0x800a9b03,
	.sfc_floor = 1ULL << 31,
	.sfc_ceil = 0
}, {
	.sfc_types = STDBIT_TEST_U32,
	.sfc_val = UINT32_MAX,
	.sfc_floor = 1ULL << 31,
	.sfc_ceil = 0
}, {
	.sfc_types = STDBIT_TEST_64P,
	.sfc_val = UINT32_MAX,
	.sfc_floor = 1ULL << 31,
	.sfc_ceil = 1ULL << 32
}, {
	.sfc_types = STDBIT_TEST_U64,
	.sfc_val = 0x0089a23b1389ba87,
	.sfc_floor = 1ULL << 55,
	.sfc_ceil = 1ULL << 56
}, {
	.sfc_types = STDBIT_TEST_U64,
	.sfc_val = 0x499aff6eb12e7777,
	.sfc_floor = 1ULL << 62,
	.sfc_ceil = 1ULL << 63
}, {
	.sfc_types = STDBIT_TEST_U64,
	.sfc_val = 0xc00123481980ab87,
	.sfc_floor = 1ULL << 63,
	.sfc_ceil = 0
}, {
	.sfc_types = STDBIT_TEST_U64,
	.sfc_val = UINT64_MAX,
	.sfc_floor = 1ULL << 63,
	.sfc_ceil = 0
} };

static bool
stdbit_fc_test_one(const stdbit_fc_test_t *test)
{
	bool ret = true;

	VERIFY3U(test->sfc_types, !=, 0);
	if ((test->sfc_types & STDBIT_TEST_U8) != 0) {
		uint64_t res = stdc_bit_floor_uc(test->sfc_val);
		if (res != test->sfc_floor) {
			warnx("TEST FAILED: Bit Floor (0x%" PRIx64 ") 8-bit "
			    "(uchar) returned 0x%" PRIx64 ", expected 0x%"
			    PRIx64, test->sfc_val, res, test->sfc_floor);
			ret = false;
		}

		res = stdc_bit_ceil_uc(test->sfc_val);
		if (res != test->sfc_ceil) {
			warnx("TEST FAILED: Bit Ceiling (0x%" PRIx64 ") 8-bit "
			    "(uchar) returned 0x%" PRIx64 ", expected 0x%"
			    PRIx64, test->sfc_val, res, test->sfc_ceil);
			ret = false;
		}
	}

	if ((test->sfc_types & STDBIT_TEST_U16) != 0) {
		uint64_t res = stdc_bit_floor_us(test->sfc_val);
		if (res != test->sfc_floor) {
			warnx("TEST FAILED: Bit Floor (0x%" PRIx64 ") 16-bit "
			    "(ushort) returned 0x%" PRIx64 ", expected 0x%"
			    PRIx64, test->sfc_val, res, test->sfc_floor);
			ret = false;
		}

		res = stdc_bit_ceil_us(test->sfc_val);
		if (res != test->sfc_ceil) {
			warnx("TEST FAILED: Bit Ceiling (0x%" PRIx64 ") 16-bit "
			    "(ushort) returned 0x%" PRIx64 ", expected 0x%"
			    PRIx64, test->sfc_val, res, test->sfc_ceil);
			ret = false;
		}
	}

	if ((test->sfc_types & STDBIT_TEST_U32) != 0) {
		uint64_t res = stdc_bit_floor_ui(test->sfc_val);
		if (res != test->sfc_floor) {
			warnx("TEST FAILED: Bit Floor (0x%" PRIx64 ") 32-bit "
			    "(uint) returned 0x%" PRIx64 ", expected 0x%"
			    PRIx64, test->sfc_val, res, test->sfc_floor);
			ret = false;
		}

		res = stdc_bit_ceil_ui(test->sfc_val);
		if (res != test->sfc_ceil) {
			warnx("TEST FAILED: Bit Ceiling (0x%" PRIx64 ") 32-bit "
			    "(uint) returned 0x%" PRIx64 ", expected 0x%"
			    PRIx64, test->sfc_val, res, test->sfc_ceil);
			ret = false;
		}

#ifdef	_ILP32
		res = stdc_bit_floor_ul(test->sfc_val);
		if (res != test->sfc_floor) {
			warnx("TEST FAILED: Bit Floor (0x%" PRIx64 ") 32-bit "
			    "(ulong) returned 0x%" PRIx64 ", expected 0x%"
			    PRIx64, test->sfc_val, res, test->sfc_floor);
			ret = false;
		}

		res = stdc_bit_ceil_ul(test->sfc_val);
		if (res != test->sfc_ceil) {
			warnx("TEST FAILED: Bit Ceiling (0x%" PRIx64 ") 32-bit "
			    "(ulong) returned 0x%" PRIx64 ", expected 0x%"
			    PRIx64, test->sfc_val, res, test->sfc_ceil);
			ret = false;
		}
#endif	/* _ILP32 */
	}

	if ((test->sfc_types & STDBIT_TEST_U64) != 0) {
		uint64_t res;

#ifdef	_LP64
		res = stdc_bit_floor_ul(test->sfc_val);
		if (res != test->sfc_floor) {
			warnx("TEST FAILED: Bit Floor (0x%" PRIx64 ") 64-bit "
			    "(ulong) returned 0x%" PRIx64 ", expected 0x%"
			    PRIx64, test->sfc_val, res, test->sfc_floor);
			ret = false;
		}

		res = stdc_bit_ceil_ul(test->sfc_val);
		if (res != test->sfc_ceil) {
			warnx("TEST FAILED: Bit Ceiling (0x%" PRIx64 ") 64-bit "
			    "(ulong) returned 0x%" PRIx64 ", expected 0x%"
			    PRIx64, test->sfc_val, res, test->sfc_ceil);
			ret = false;
		}
#endif	/* _LP64 */

		res = stdc_bit_floor_ull(test->sfc_val);
		if (res != test->sfc_floor) {
			warnx("TEST FAILED: Bit Floor (0x%" PRIx64 ") 64-bit "
			    "(ulong long) returned 0x%" PRIx64 ", expected 0x%"
			    PRIx64, test->sfc_val, res, test->sfc_floor);
			ret = false;
		}

		res = stdc_bit_ceil_ull(test->sfc_val);
		if (res != test->sfc_ceil) {
			warnx("TEST FAILED: Bit Ceiling (0x%" PRIx64 ") 64-bit "
			    "(ulong long) returned 0x%" PRIx64 ", expected 0x%"
			    PRIx64, test->sfc_val, res, test->sfc_ceil);
			ret = false;
		}
	}

	if (ret) {
		stdbit_print_pass(test->sfc_types, test->sfc_val,
		    "Bit Floor/Ceiling");
	}

	return (ret);

}

int
main(void)
{
	int ret = EXIT_SUCCESS;

	for (size_t i = 0; i < ARRAY_SIZE(stdbit_groups); i++) {
		for (size_t t = 0; t < stdbit_groups[i].sg_ntests; t++) {
			if (!stdbit_test_one(&stdbit_groups[i].sg_tests[t],
			    stdbit_groups[i].sg_ops)) {
				ret = EXIT_FAILURE;
			}
		}
	}

	for (size_t i = 0; i < ARRAY_SIZE(stdbit_1b_tests); i++) {
		if (!stdbit_1b_test_one(&stdbit_1b_tests[i])) {
			ret = EXIT_FAILURE;
		}
	}

	for (size_t i = 0; i < ARRAY_SIZE(stdbit_fc_tests); i++) {
		if (!stdbit_fc_test_one(&stdbit_fc_tests[i])) {
			ret = EXIT_FAILURE;
		}
	}

	if (ret == EXIT_SUCCESS) {
		(void) printf("All tests passed successfully\n");
	}

	return (ret);
}
