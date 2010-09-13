/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */

/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	BASE_CONVERSION_H
#define	BASE_CONVERSION_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <errno.h>
#include <floatingpoint.h>
#include <sys/isa_defs.h>

/*
 * Common constants, types, and declarations for floating point
 * base conversion
 */

/* PRIVATE CONSTANTS	 */

/* exponent bias */
#define	SINGLE_BIAS	  127
#define	DOUBLE_BIAS	 1023
#define	EXTENDED_BIAS	16383
#define	QUAD_BIAS	16383


/* PRIVATE TYPES */

/*
 * Unpacked binary floating point format.  The binary point lies
 * to the right of the most significant bit in significand[0].
 * The exponent is unbiased.  The significand array is long enough
 * that the last word never contains any bits we need to keep,
 * just rounding information.
 */

#define	UNPACKED_SIZE	5

typedef struct {
	int		sign;
	enum fp_class_type fpclass;
	int		exponent;
	unsigned	significand[UNPACKED_SIZE];
} unpacked;

/*
 * Packed binary floating point formats.  The *_msw structure
 * corresponds to the most significant word.
 */

#ifdef _LITTLE_ENDIAN

typedef struct {
	unsigned	significand:23;
	unsigned	exponent:8;
	unsigned	sign:1;
} single_msw;

typedef struct {
	unsigned	significand:20;
	unsigned	exponent:11;
	unsigned	sign:1;
} double_msw;

typedef struct {
	unsigned	exponent:15;
	unsigned	sign:1;
	unsigned	unused:16;
} extended_msw;

typedef struct {
	unsigned	significand:16;
	unsigned	exponent:15;
	unsigned	sign:1;
} quadruple_msw;

typedef struct {
	single_msw	msw;
} single_formatted;

typedef struct {
	unsigned	significand2;
	double_msw	msw;
} double_formatted;

typedef struct {
	unsigned	significand2;
	unsigned	significand;
	extended_msw	msw;
} extended_formatted;

typedef struct {
	unsigned	significand4;
	unsigned	significand3;
	unsigned	significand2;
	quadruple_msw	msw;
} quadruple_formatted;

#else

typedef struct {
	unsigned	sign:1;
	unsigned	exponent:8;
	unsigned	significand:23;
} single_msw;

typedef struct {
	unsigned	sign:1;
	unsigned	exponent:11;
	unsigned	significand:20;
} double_msw;

typedef struct {
	unsigned	sign:1;
	unsigned	exponent:15;
	unsigned	unused:16;
} extended_msw;

typedef struct {
	unsigned	sign:1;
	unsigned	exponent:15;
	unsigned	significand:16;
} quadruple_msw;

typedef struct {
	single_msw	msw;
} single_formatted;

typedef struct {
	double_msw	msw;
	unsigned	significand2;
} double_formatted;

typedef struct {
	extended_msw	msw;
	unsigned	significand;
	unsigned	significand2;
} extended_formatted;

typedef struct {
	quadruple_msw   msw;
	unsigned	significand2;
	unsigned	significand3;
	unsigned	significand4;
} quadruple_formatted;

#endif

typedef union {
	single_formatted f;
	single		x;
} single_equivalence;

typedef union {
	double_formatted f;
	double		x;
} double_equivalence;

typedef union {
	extended_formatted f;
	extended	x;
} extended_equivalence;

typedef union {
	quadruple_formatted f;
	quadruple	x;
} quadruple_equivalence;

/*
 * Multiple precision floating point type.  This type is suitable
 * for representing positive floating point numbers of variable
 * precision in either binary or decimal.  The bsignificand array
 * holds the digits of a multi-word integer, stored least significant
 * digit first, in either radix 2^16 or 10^4.  blength is the
 * length of the significand array.  bexponent is a power of two
 * or ten, so that the value represented is
 *
 *   2^(bexponent) * sum (bsignificand[i] * 2^(i*16))
 *
 * if binary, or
 *
 *   10^(bexponent) * sum (bsignificand[i] * 10^(i*4))
 *
 * if decimal, where the sum runs from i = 0 to blength - 1.
 * (Whether the representation is binary or decimal is implied
 * from context.)  bsize indicates the size of the significand
 * array and may be larger than _BIG_FLOAT_SIZE if storage has
 * been allocated at runtime.
 */

#define	_BIG_FLOAT_SIZE	(DECIMAL_STRING_LENGTH/2)

typedef struct {
	unsigned short  bsize;
	unsigned short  blength;
	short int	bexponent;
	unsigned short	bsignificand[_BIG_FLOAT_SIZE];
} _big_float;

/* structure for storing IEEE modes and status flags */
typedef struct {
	int	status, mode;
} __ieee_flags_type;


/* PRIVATE GLOBAL VARIABLES */

/*
 * Thread-specific flags to indicate whether any NaNs or infinities
 * have been read or written.
 */
extern int *_thrp_get_inf_read(void);
extern int *_thrp_get_inf_written(void);
extern int *_thrp_get_nan_read(void);
extern int *_thrp_get_nan_written(void);

#define	__inf_read		(*(int *)_thrp_get_inf_read())
#define	__inf_written		(*(int *)_thrp_get_inf_written())
#define	__nan_read		(*(int *)_thrp_get_nan_read())
#define	__nan_written		(*(int *)_thrp_get_nan_written())

/*
 * Powers of 5 in base 2**16 and powers of 2 in base 10**4.
 *
 * __tbl_10_small_digits	contains
 *	5**0,
 *	5**1, ...
 *	5**__TBL_10_SMALL_SIZE-1
 * __tbl_10_big_digits		contains
 *	5**0,
 *	5**__TBL_10_SMALL_SIZE, ...
 *	5**__TBL_10_SMALL_SIZE*(__TBL_10_BIG_SIZE-1)
 * __tbl_10_huge_digits		contains
 *	5**0,
 *	5**__TBL_10_SMALL_SIZE*__TBL_10_BIG_SIZE, ...
 *	5**__TBL_10_SMALL_SIZE*__TBL_10_BIG_SIZE*(__TBL_10_HUGE_SIZE-1)
 *
 * so that any power of 5 from 5**0 to
 *	5**__TBL_10_SMALL_SIZE*__TBL_10_BIG_SIZE*__TBL_10_HUGE_SIZE
 * can be represented as a product of at most three table entries.
 *
 * Similarly any power of 2 from 2**0 to
 *	2**__TBL_2_SMALL_SIZE*__TBL_2_BIG_SIZE*__TBL_2_HUGE_SIZE
 * can be represented as a product of at most three table entries.
 *
 * Since the powers vary greatly in size, the tables are condensed:
 * entry i in table x is stored in
 *	x_digits[x_start[i]] (least significant)
 * through
 *	x_digits[x_start[i+1]-1] (most significant)
 */

#define	__TBL_10_SMALL_SIZE	64
#define	__TBL_10_BIG_SIZE	16
#define	__TBL_10_HUGE_SIZE	6

extern const unsigned short
	__tbl_10_small_digits[], __tbl_10_small_start[],
	__tbl_10_big_digits[], __tbl_10_big_start[],
	__tbl_10_huge_digits[], __tbl_10_huge_start[];

#define	__TBL_2_SMALL_SIZE	176
#define	__TBL_2_BIG_SIZE	16
#define	__TBL_2_HUGE_SIZE	6

extern const unsigned short
	__tbl_2_small_digits[], __tbl_2_small_start[],
	__tbl_2_big_digits[], __tbl_2_big_start[],
	__tbl_2_huge_digits[], __tbl_2_huge_start[];

/*
 * Powers of ten.  For i = 0, 1, ..., __TBL_TENS_MAX, __tbl_tens[i]
 * = 10^i rounded to double precision.  (10^i is representable exactly
 * in double precision for i <= __TBL_TENS_EXACT.)
 */

#define	__TBL_TENS_EXACT	22
#define	__TBL_TENS_MAX		49

extern const double __tbl_tens[];


/* PRIVATE FUNCTIONS */

extern void __base_conversion_set_exception(fp_exception_field_type);

extern void __four_digits_quick(unsigned short, char *);

extern int __fast_double_to_decimal(double *dd, decimal_mode *pm,
		decimal_record *pd, fp_exception_field_type *ps);

extern void __pack_single(unpacked *, single *, enum fp_direction_type,
		fp_exception_field_type *);
extern void __pack_double(unpacked *, double *, enum fp_direction_type,
		fp_exception_field_type *);
extern void __pack_extended(unpacked *, extended *, enum fp_direction_type,
		fp_exception_field_type *);
extern void __pack_quadruple(unpacked *, quadruple *,
		enum fp_direction_type, fp_exception_field_type *);

extern void __infnanstring(enum fp_class_type cl, int ndigits, char *buf);

extern void __big_float_times_power(_big_float *pbf, int mult, int n,
		int precision, _big_float **pnewbf);

extern void __get_ieee_flags(__ieee_flags_type *);
extern void __set_ieee_flags(__ieee_flags_type *);

extern double __mul_set(double, double, int *);
extern double __div_set(double, double, int *);
extern double __dabs(double *);

#if defined(sparc) || defined(__sparc)
extern enum fp_direction_type _QgetRD(void);
#endif

#include "base_inlines.h"

#endif	/* BASE_CONVERSION_H */
