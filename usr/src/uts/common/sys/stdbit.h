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
 * Copyright 2024 Oxide Computer Company
 */

#ifndef _SYS_STDBIT_H
#define	_SYS_STDBIT_H

/*
 * This header implements all of the different aspects of the C23 stdbit.h
 * functionality. We attempt to make this header useful to all C versions other
 * than the type generic interfaces, for which we require the asked for version
 * of C to be at least C23. The functions that are present here are allowed to
 * be inline or not. To provide wider ranging compiler support we declare extern
 * versions of all of these symbols which are provided in both libc and the
 * kernel. This also avoids cases where a compiler builtin relies on external
 * runtime library support.
 *
 * In the future, we should provide inline versions with compilers that support
 * common builtins.
 */

#include <sys/feature_tests.h>
#include <sys/isa_defs.h>

/*
 * This header is required specifically to make the size_t, uintXX_t, and the
 * _least_ variants available. The generic values are allowed to leverage the
 * 'bool' type. In C23, bool became a keyword as opposed to a definition to
 * _Bool. We therefore include it so we can attempt to be consistent and
 * generally useful.
 */
#include <sys/int_types.h>
#include <sys/stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Declare our version.
 */
#define	__STDC_VERSION_STDBIT_H__	202311L

#if !defined(_SIZE_T) || __cplusplus >= 199711L
#define	_SIZE_T
#if defined(_LP64) || defined(_I32LPx)
typedef unsigned long size_t;   /* size of something in bytes */
#else
typedef unsigned int size_t;    /* (historical version) */
#endif
#endif  /* _SIZE_T */

/*
 * Endian values and detection.
 */
#define	__STDC_ENDIAN_LITTLE__	1234
#define	__STDC_ENDIAN_BIG__	4321
#if defined(_LITTLE_ENDIAN)
#define	__STDC_ENDIAN_NATIVE__	__STDC_ENDIAN_LITTLE__
#elif defined(_BIG_ENDIAN)
#define	__STDC_ENDIAN_NATIVE__	__STDC_ENDIAN_BIG__
#else
#error	"Unknown byte order"
#endif	/* _LITTLE_ENDIAN */

/*
 * Count Leading Zeros
 */
extern unsigned int stdc_leading_zeros_uc(unsigned char) _C23_UNSEQ_ATTR;
extern unsigned int stdc_leading_zeros_us(unsigned short) _C23_UNSEQ_ATTR;
extern unsigned int stdc_leading_zeros_ui(unsigned int) _C23_UNSEQ_ATTR;
extern unsigned int stdc_leading_zeros_ul(unsigned long) _C23_UNSEQ_ATTR;

/*
 * Count Leading Ones
 */
extern unsigned int stdc_leading_ones_uc(unsigned char) _C23_UNSEQ_ATTR;
extern unsigned int stdc_leading_ones_us(unsigned short) _C23_UNSEQ_ATTR;
extern unsigned int stdc_leading_ones_ui(unsigned int) _C23_UNSEQ_ATTR;
extern unsigned int stdc_leading_ones_ul(unsigned long) _C23_UNSEQ_ATTR;

/*
 * Count Trailing Zeros
 */
extern unsigned int stdc_trailing_zeros_uc(unsigned char) _C23_UNSEQ_ATTR;
extern unsigned int stdc_trailing_zeros_us(unsigned short) _C23_UNSEQ_ATTR;
extern unsigned int stdc_trailing_zeros_ui(unsigned int) _C23_UNSEQ_ATTR;
extern unsigned int stdc_trailing_zeros_ul(unsigned long) _C23_UNSEQ_ATTR;

/*
 * Count Trailing Ones
 */
extern unsigned int stdc_trailing_ones_uc(unsigned char) _C23_UNSEQ_ATTR;
extern unsigned int stdc_trailing_ones_us(unsigned short) _C23_UNSEQ_ATTR;
extern unsigned int stdc_trailing_ones_ui(unsigned int) _C23_UNSEQ_ATTR;
extern unsigned int stdc_trailing_ones_ul(unsigned long) _C23_UNSEQ_ATTR;

/*
 * First Leading Zero
 */
extern unsigned int stdc_first_leading_zero_uc(unsigned char) _C23_UNSEQ_ATTR;
extern unsigned int stdc_first_leading_zero_us(unsigned short) _C23_UNSEQ_ATTR;
extern unsigned int stdc_first_leading_zero_ui(unsigned int) _C23_UNSEQ_ATTR;
extern unsigned int stdc_first_leading_zero_ul(unsigned long) _C23_UNSEQ_ATTR;

/*
 * First Leading One
 */
extern unsigned int stdc_first_leading_one_uc(unsigned char) _C23_UNSEQ_ATTR;
extern unsigned int stdc_first_leading_one_us(unsigned short) _C23_UNSEQ_ATTR;
extern unsigned int stdc_first_leading_one_ui(unsigned int) _C23_UNSEQ_ATTR;
extern unsigned int stdc_first_leading_one_ul(unsigned long) _C23_UNSEQ_ATTR;

/*
 * First Trailing Zero
 */
extern unsigned int stdc_first_trailing_zero_uc(unsigned char) _C23_UNSEQ_ATTR;
extern unsigned int stdc_first_trailing_zero_us(unsigned short) _C23_UNSEQ_ATTR;
extern unsigned int stdc_first_trailing_zero_ui(unsigned int) _C23_UNSEQ_ATTR;
extern unsigned int stdc_first_trailing_zero_ul(unsigned long) _C23_UNSEQ_ATTR;

/*
 * First Trailing One
 */
extern unsigned int stdc_first_trailing_one_uc(unsigned char) _C23_UNSEQ_ATTR;
extern unsigned int stdc_first_trailing_one_us(unsigned short) _C23_UNSEQ_ATTR;
extern unsigned int stdc_first_trailing_one_ui(unsigned int) _C23_UNSEQ_ATTR;
extern unsigned int stdc_first_trailing_one_ul(unsigned long) _C23_UNSEQ_ATTR;

/*
 * Count Zeros
 */
extern unsigned int stdc_count_zeros_uc(unsigned char) _C23_UNSEQ_ATTR;
extern unsigned int stdc_count_zeros_us(unsigned short) _C23_UNSEQ_ATTR;
extern unsigned int stdc_count_zeros_ui(unsigned int) _C23_UNSEQ_ATTR;
extern unsigned int stdc_count_zeros_ul(unsigned long) _C23_UNSEQ_ATTR;

/*
 * Count Ones
 */
extern unsigned int stdc_count_ones_uc(unsigned char) _C23_UNSEQ_ATTR;
extern unsigned int stdc_count_ones_us(unsigned short) _C23_UNSEQ_ATTR;
extern unsigned int stdc_count_ones_ui(unsigned int) _C23_UNSEQ_ATTR;
extern unsigned int stdc_count_ones_ul(unsigned long) _C23_UNSEQ_ATTR;

/*
 * Single-bit Check
 */
extern bool stdc_has_single_bit_uc(unsigned char) _C23_UNSEQ_ATTR;
extern bool stdc_has_single_bit_us(unsigned short) _C23_UNSEQ_ATTR;
extern bool stdc_has_single_bit_ui(unsigned int) _C23_UNSEQ_ATTR;
extern bool stdc_has_single_bit_ul(unsigned long) _C23_UNSEQ_ATTR;

/*
 * Bit Width
 */
extern unsigned int stdc_bit_width_uc(unsigned char) _C23_UNSEQ_ATTR;
extern unsigned int stdc_bit_width_us(unsigned short) _C23_UNSEQ_ATTR;
extern unsigned int stdc_bit_width_ui(unsigned int) _C23_UNSEQ_ATTR;
extern unsigned int stdc_bit_width_ul(unsigned long) _C23_UNSEQ_ATTR;

/*
 * Bit Floor
 */
extern unsigned char stdc_bit_floor_uc(unsigned char) _C23_UNSEQ_ATTR;
extern unsigned short stdc_bit_floor_us(unsigned short) _C23_UNSEQ_ATTR;
extern unsigned int stdc_bit_floor_ui(unsigned int) _C23_UNSEQ_ATTR;
extern unsigned long stdc_bit_floor_ul(unsigned long) _C23_UNSEQ_ATTR;

/*
 * Bit Ceiling
 */
extern unsigned char stdc_bit_ceil_uc(unsigned char) _C23_UNSEQ_ATTR;
extern unsigned short stdc_bit_ceil_us(unsigned short) _C23_UNSEQ_ATTR;
extern unsigned int stdc_bit_ceil_ui(unsigned int) _C23_UNSEQ_ATTR;
extern unsigned long stdc_bit_ceil_ul(unsigned long) _C23_UNSEQ_ATTR;

/*
 * long long variants of functions. This check is just for some non-C23
 * environments out of courtesy.
 */
#if defined(_LONGLONG_TYPE)
extern unsigned int stdc_leading_zeros_ull(unsigned long long) _C23_UNSEQ_ATTR;
extern unsigned int stdc_leading_ones_ull(unsigned long long) _C23_UNSEQ_ATTR;
extern unsigned int stdc_trailing_zeros_ull(unsigned long long) _C23_UNSEQ_ATTR;
extern unsigned int stdc_trailing_ones_ull(unsigned long long) _C23_UNSEQ_ATTR;
extern unsigned int stdc_first_leading_zero_ull(unsigned long long)
    _C23_UNSEQ_ATTR;
extern unsigned int stdc_first_leading_one_ull(unsigned long long)
    _C23_UNSEQ_ATTR;
extern unsigned int stdc_first_trailing_zero_ull(unsigned long long)
    _C23_UNSEQ_ATTR;
extern unsigned int stdc_first_trailing_one_ull(unsigned long long)
    _C23_UNSEQ_ATTR;
extern unsigned int stdc_count_zeros_ull(unsigned long long) _C23_UNSEQ_ATTR;
extern unsigned int stdc_count_ones_ull(unsigned long long) _C23_UNSEQ_ATTR;
extern bool stdc_has_single_bit_ull(unsigned long long) _C23_UNSEQ_ATTR;
extern unsigned int stdc_bit_width_ull(unsigned long long) _C23_UNSEQ_ATTR;
extern unsigned long long stdc_bit_floor_ull(unsigned long long)
    _C23_UNSEQ_ATTR;
extern unsigned long long stdc_bit_ceil_ull(unsigned long long) _C23_UNSEQ_ATTR;
#endif	/* _LONGLONG_TYPE */

/*
 * Type Generic functions. The standard requires that these be a generic return
 * type that operates on the following types of values:
 *
 *  - Standard unsigned integer types (excluding bool) i.e. 'unsigned int'.
 *  - Extended unsigned integer types i.e. 'uint128_t' which is not something
 *    currently supported and up to the platform.
 *  - Bit-precise integers that match standard or extended integers. This means
 *    that _BitInt(32) is accepted, but a value that basically doesn't match a
 *    uint8_t, uint16_t, uint32_t, or uint64_t like _BitInt(48) is not valid.
 *
 * There currently is no way to match ranges of _BitInt in the _Generic macro so
 * we end up focusing on the size of the type that was passed. _Generic matches
 * on the type of the first expression, so rather than just the base type of the
 * value, we instead use a suggestion to transform it into a fixed-length array.
 * This works for signed and unsigned integers, implicitly doing a cast to the
 * unsigned value for signed integers. Similarly, this incidentally works for
 * signed and unsigned _BitInt() values that are able to be translated into
 * standard sizes.  We always use the ull versions for 64-bit values as that is
 * always 64-bit regardless if we're in an ILP32 or LP64 environment.
 *
 * _Generic was introduced in C11. As we currently don't have any _Generic
 * statements that aren't valid in C11, we reduce our guard for these to C11 as
 * there isn't really a good way to test for the presence of the _Generic
 * construct otherwise. If we end up having to modify these to use more explicit
 * types, we'll have to have per-standard versions of these macros.
 */
#if defined(_STDC_C11)
/* CSTYLED */
#define	stdc_leading_zeros(val)	_Generic((char(*)[sizeof (val)]){ 0 },	\
    char(*)[1]:	stdc_leading_zeros_uc(val),	\
    char(*)[2]:	stdc_leading_zeros_us(val),	\
    char(*)[4]:	stdc_leading_zeros_ui(val),	\
    char(*)[8]:	stdc_leading_zeros_ull(val))

/* CSTYLED */
#define	stdc_leading_ones(val)	_Generic((char(*)[sizeof (val)]){ 0 },	\
    char(*)[1]:	stdc_leading_ones_uc(val),	\
    char(*)[2]:	stdc_leading_ones_us(val),	\
    char(*)[4]:	stdc_leading_ones_ui(val),	\
    char(*)[8]:	stdc_leading_ones_ull(val))

/* CSTYLED */
#define	stdc_trailing_zeros(val)	_Generic((char(*)[sizeof (val)]){ 0 }, \
    char(*)[1]:	stdc_trailing_zeros_uc(val),	\
    char(*)[2]:	stdc_trailing_zeros_us(val),	\
    char(*)[4]:	stdc_trailing_zeros_ui(val),	\
    char(*)[8]:	stdc_trailing_zeros_ull(val))

/* CSTYLED */
#define	stdc_trailing_ones(val)	_Generic((char(*)[sizeof (val)]){ 0 },	\
    char(*)[1]:	stdc_trailing_ones_uc(val),	\
    char(*)[2]:	stdc_trailing_ones_us(val),	\
    char(*)[4]:	stdc_trailing_ones_ui(val),	\
    char(*)[8]:	stdc_trailing_ones_ull(val))

/* CSTYLED */
#define	stdc_first_leading_zero(val)	_Generic((char(*)[sizeof (val)]){ 0 }, \
    char(*)[1]:	stdc_first_leading_zero_uc(val),	\
    char(*)[2]:	stdc_first_leading_zero_us(val),	\
    char(*)[4]:	stdc_first_leading_zero_ui(val),	\
    char(*)[8]:	stdc_first_leading_zero_ull(val))

/* CSTYLED */
#define	stdc_first_leading_one(val)	_Generic((char(*)[sizeof (val)]){ 0 }, \
    char(*)[1]:	stdc_first_leading_one_uc(val),	\
    char(*)[2]:	stdc_first_leading_one_us(val),	\
    char(*)[4]:	stdc_first_leading_one_ui(val),	\
    char(*)[8]:	stdc_first_leading_one_ull(val))

/* CSTYLED */
#define	stdc_first_trailing_zero(val)	_Generic((char(*)[sizeof (val)]){ 0 }, \
    char(*)[1]:	stdc_first_trailing_zero_uc(val),	\
    char(*)[2]:	stdc_first_trailing_zero_us(val),	\
    char(*)[4]:	stdc_first_trailing_zero_ui(val),	\
    char(*)[8]:	stdc_first_trailing_zero_ull(val))

/* CSTYLED */
#define	stdc_first_trailing_one(val)	_Generic((char(*)[sizeof (val)]){ 0 }, \
    char(*)[1]:	stdc_first_trailing_one_uc(val),	\
    char(*)[2]:	stdc_first_trailing_one_us(val),	\
    char(*)[4]:	stdc_first_trailing_one_ui(val),	\
    char(*)[8]:	stdc_first_trailing_one_ull(val))

/* CSTYLED */
#define	stdc_count_zeros(val)	_Generic((char(*)[sizeof (val)]){ 0 },	\
    char(*)[1]:	stdc_count_zeros_uc(val),	\
    char(*)[2]:	stdc_count_zeros_us(val),	\
    char(*)[4]:	stdc_count_zeros_ui(val),	\
    char(*)[8]:	stdc_count_zeros_ull(val))

/* CSTYLED */
#define	stdc_count_ones(val)	_Generic((char(*)[sizeof (val)]){ 0 },	\
    char(*)[1]:	stdc_count_ones_uc(val),	\
    char(*)[2]:	stdc_count_ones_us(val),	\
    char(*)[4]:	stdc_count_ones_ui(val),	\
    char(*)[8]:	stdc_count_ones_ull(val))

/* CSTYLED */
#define	stdc_has_single_bit(val)	_Generic((char(*)[sizeof (val)]){ 0 }, \
    char(*)[1]:	stdc_has_single_bit_uc(val),	\
    char(*)[2]:	stdc_has_single_bit_us(val),	\
    char(*)[4]:	stdc_has_single_bit_ui(val),	\
    char(*)[8]:	stdc_has_single_bit_ull(val))

/* CSTYLED */
#define	stdc_bit_width(val)	_Generic((char(*)[sizeof (val)]){ 0 },	\
    char(*)[1]:	stdc_bit_width_uc(val),	\
    char(*)[2]:	stdc_bit_width_us(val),	\
    char(*)[4]:	stdc_bit_width_ui(val),	\
    char(*)[8]:	stdc_bit_width_ull(val))

/* CSTYLED */
#define	stdc_bit_floor(val)	_Generic((char(*)[sizeof (val)]){ 0 },	\
    char(*)[1]:	stdc_bit_floor_uc(val),	\
    char(*)[2]:	stdc_bit_floor_us(val),	\
    char(*)[4]:	stdc_bit_floor_ui(val),	\
    char(*)[8]:	stdc_bit_floor_ull(val))

/* CSTYLED */
#define	stdc_bit_ceil(val)	_Generic((char(*)[sizeof (val)]){ 0 },	\
    char(*)[1]:	stdc_bit_ceil_uc(val),	\
    char(*)[2]:	stdc_bit_ceil_us(val),	\
    char(*)[4]:	stdc_bit_ceil_ui(val),	\
    char(*)[8]:	stdc_bit_ceil_ull(val))
#endif	/* STDC_C11 */

#ifdef __cplusplus
}
#endif

#endif /* _SYS_STDBIT_H */
