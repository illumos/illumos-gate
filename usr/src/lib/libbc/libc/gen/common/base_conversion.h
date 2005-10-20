/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 1995 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_base_conversion_h
#define	_base_conversion_h

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <errno.h>

#include <floatingpoint.h>

#ifdef DEBUG
#include <stdio.h>
#include <assert.h>
#endif

/* Sun floating-point PRIVATE include file.  */

/* PRIVATE MACROS	 */

#ifdef DEBUG
#define PRIVATE
#else
#define PRIVATE static
#endif

/* PRIVATE CONSTANTS	 */

#define	SINGLE_BIAS	  127
#define DOUBLE_BIAS	 1023
#define EXTENDED_BIAS	16383
#define QUAD_BIAS	16383

#define SINGLE_MAXE	  97	/* Maximum decimal exponent we need to
				 * consider. */
#define DOUBLE_MAXE	 771	/* Maximum decimal exponent we need to
				 * consider. */
#define EXTENDED_MAXE  12330	/* Maximum decimal exponent we need to
				 * consider. */
#define QUAD_MAXE  12330	/* Maximum decimal exponent we need to
				 * consider. */

#define UNPACKED_SIZE	5	/* Size of unpacked significand.  */

/* PRIVATE TYPES 	 */

/*
 * Unpack floating-point internal format.
 * Value is 0.s0s1..sn * 2**(1+exponent)
 */
typedef struct {		
	int             sign;
	enum fp_class_type fpclass;
	int             exponent;	/* Unbiased exponent. */
	unsigned        significand[UNPACKED_SIZE];	/* Last word is round */
							/* and sticky. */
} unpacked;

#ifdef i386
typedef struct {		/* Most significant word formats. */
	unsigned        significand:23;
	unsigned        exponent:8;
	unsigned        sign:1;
} single_msw;

typedef struct {
	unsigned        significand:20;
	unsigned        exponent:11;
	unsigned        sign:1;
} double_msw;

typedef struct {
	unsigned        exponent:15;
	unsigned        sign:1;
	unsigned        unused:16;
} extended_msw;

typedef struct {
	unsigned        significand:16;
	unsigned        exponent:15;
	unsigned        sign:1;
} quadruple_msw;

typedef struct {		/* Floating-point formats in detail. */
	single_msw      msw;
} single_formatted;

typedef struct {
	unsigned        significand2;
	double_msw      msw;
} double_formatted;

typedef struct {
	unsigned        significand2;
	unsigned        significand;
	extended_msw    msw;
} extended_formatted;

typedef struct {
	unsigned        significand4;
	unsigned        significand3;
	unsigned        significand2;
	quadruple_msw   msw;
} quadruple_formatted;
#else
typedef struct {		/* Most significant word formats. */
	unsigned        sign:1;
	unsigned        exponent:8;
	unsigned        significand:23;
} single_msw;

typedef struct {
	unsigned        sign:1;
	unsigned        exponent:11;
	unsigned        significand:20;
} double_msw;

typedef struct {
	unsigned        sign:1;
	unsigned        exponent:15;
	unsigned        unused:16;
} extended_msw;

typedef struct {
	unsigned        sign:1;
	unsigned        exponent:15;
	unsigned        significand:16;
} quadruple_msw;

typedef struct {		/* Floating-point formats in detail. */
	single_msw      msw;
} single_formatted;

typedef struct {
	double_msw      msw;
	unsigned        significand2;
} double_formatted;

typedef struct {
	extended_msw    msw;
	unsigned        significand;
	unsigned        significand2;
} extended_formatted;

typedef struct {
	quadruple_msw   msw;
	unsigned        significand2;
	unsigned        significand3;
	unsigned        significand4;
} quadruple_formatted;
#endif

typedef union {			/* Floating-point formats equivalenced. */
	single_formatted f;
	single          x;
} single_equivalence;

typedef union {
	double_formatted f;
	double          x;
} double_equivalence;

typedef union {
	extended_formatted f;
	extended        x;
} extended_equivalence;

typedef union {
	quadruple_formatted f;
	quadruple       x;
} quadruple_equivalence;

/* PRIVATE GLOBAL VARIABLES */

/* Current floating-point exceptions. */
fp_exception_field_type _fp_current_exceptions;

/* Current rounding direction. */
enum fp_direction_type	_fp_current_direction;

/* Current rounding precision. */
enum fp_precision_type	_fp_current_precision;

/* PRIVATE FUNCTIONS */

extern void _fp_set_exception(enum fp_exception_type);
/* enum fp_exception_type ex ; */	/* exception to be set in curexcep */

/*
 * Default size for _big_float - suitable for single and double precision.
 */

#define _BIG_FLOAT_SIZE	(DECIMAL_STRING_LENGTH/2)
#define _BIG_FLOAT_DIGIT short unsigned	/* big_float significand type */

/* Maximum number of integer digits in a representable extended or quad. */
#define _INTEGER_SIZE	4932	

typedef struct {		/* Variable-precision floating-point type */
				/* used for intermediate results.	 */
	unsigned short  bsize;	/* Maximum allowable logical length of */
				/* significand. */
	unsigned short  blength;	/* Logical length of significand. */
	short int       bexponent;	/*
					 * Exponent to be attached to least
					 * significant word of significand.
					 * exponent >= 0 implies all integer,
					 * with decimal point to right of
					 * least significant word of
					 * significand, and is equivalent to
					 * number of omitted trailing zeros
					 * of significand. -length < exponent
					 * < 0  implies decimal point within
					 * significand. exponent = -length
					 * implies decimal point to left of
					 * most significand word. exponent <
					 * -length implies decimal point to
					 * left of most significant word with
					 * -length-exponent leading zeros.
					 */
	/*
	 * NOTE: bexponent represents a power of 2 or 10, even though big
	 * digits are powers of 2**16 or 10**4.
	 */
	_BIG_FLOAT_DIGIT bsignificand[_BIG_FLOAT_SIZE];
	/*
	 * Significand of digits in base 10**4 or 2**16. significand[0] is
	 * least significant, significand[length-1] is most significant.
	 */
} _big_float;

#define BIG_FLOAT_TIMES_NOMEM	(_big_float *)0
#define BIG_FLOAT_TIMES_TOOBIG	(_big_float *)1

/* Internal functions defined in base conversion support routines. */

extern void     _multiply_base_ten(_big_float *, _BIG_FLOAT_DIGIT);
extern void     _multiply_base_ten_by_two(_big_float *, short unsigned);
extern void     _multiply_base_two(_big_float *, _BIG_FLOAT_DIGIT,
    long unsigned);
extern void     _carry_propagate_two(unsigned long, _BIG_FLOAT_DIGIT *);
extern void     _carry_propagate_ten(unsigned long, _BIG_FLOAT_DIGIT *);
extern void     _multiply_base_two_vector(short unsigned, _BIG_FLOAT_DIGIT *,
    short unsigned *, _BIG_FLOAT_DIGIT []);
extern void     _multiply_base_ten_vector(short unsigned, _BIG_FLOAT_DIGIT *,
    short unsigned *, _BIG_FLOAT_DIGIT []);
extern void     _fourdigitsquick(short unsigned, char*);
extern void     _unpacked_to_big_float(unpacked *, _big_float *, int *);
extern void     _big_binary_to_big_decimal(_big_float *, _big_float *);
extern void     _left_shift_base_ten(_big_float *, short unsigned);
extern void     _left_shift_base_two(_big_float *, short unsigned);
extern void     _right_shift_base_two(_big_float *, short unsigned,
    _BIG_FLOAT_DIGIT *);
extern void     _free_big_float(_big_float *);
extern void	_base_conversion_abort(int, char *);
extern void	_display_big_float(_big_float *, unsigned);
extern void	_integerstring_to_big_decimal(char [], unsigned, unsigned,
    unsigned *, _big_float *);
extern void	_fractionstring_to_big_decimal(char [], unsigned, unsigned,
    _big_float *);
extern void	_big_decimal_to_big_binary(_big_float *, _big_float *);
extern void	_fp_rightshift(unpacked *, int);
extern void	_fp_leftshift(unpacked *, unsigned);
extern void	_fp_normalize(unpacked *);
extern void	_pack_single(unpacked *, single *);
extern void	_pack_double(unpacked *, double *);
extern void	_pack_extended(unpacked *, extended *);
extern void	_pack_quadruple(unpacked *, quadruple *);
extern void	_unpack_single(unpacked *, single *);
extern void	_unpack_double(unpacked *, double *);
extern void	_unpack_extended(unpacked *, extended *);
extern void	_unpack_quadruple(unpacked *, quadruple *);
extern void	_unpacked_to_decimal(unpacked *, decimal_mode *,
    decimal_record *, fp_exception_field_type *);
extern enum fp_class_type	_class_single(single *);
extern enum fp_class_type	_class_double(double *);
extern enum fp_class_type	_class_extended(extended *);
extern enum fp_class_type	_class_quadruple(quadruple *);

/*
 * Fundamental utilities that multiply or add two shorts into a unsigned long, 
 * sometimes add an unsigned long carry, 
 * compute quotient and remainder in underlying base, and return
 * quo<<16 | rem as  a unsigned long.
 */

extern unsigned long _umac(_BIG_FLOAT_DIGIT, _BIG_FLOAT_DIGIT, unsigned long);
	/* p = x * y + c ; return p */

#define _prodc_b65536(x,y,c) (_umac((x),(y),(c)))

extern unsigned long _prodc_b10000(_BIG_FLOAT_DIGIT, _BIG_FLOAT_DIGIT,
    unsigned long);
/* p = x * y + c ; return (p/10000 << */

extern unsigned long _prod_b10000(_BIG_FLOAT_DIGIT, _BIG_FLOAT_DIGIT);
/* p = x * y ; return (p/10000 << 16 | p%10000) */

extern unsigned long _prod_10000_b65536(_BIG_FLOAT_DIGIT, long unsigned);
/* p = x * 10000 + c ; return p */

extern unsigned long _prod_65536_b10000(_BIG_FLOAT_DIGIT, long unsigned);
/* p = x * 65536 + c ; return (p/10000 << 16 | p%10000) */

#define _rshift_b65536(x,n,c) ((((unsigned long) (x)) << (16-(n))) + ((c)<<16))

#define _lshift_b65536(x,n,c) ((((unsigned long) (x)) << (n)) + (c))

extern unsigned long _lshift_b10000(_BIG_FLOAT_DIGIT, _BIG_FLOAT_DIGIT,
    long unsigned);
/* p = x << n + c ; return (p/10000 << 16 | p%10000) */

#define _carry_in_b65536(x,c) ((x) + (c))

extern unsigned long _carry_in_b10000(_BIG_FLOAT_DIGIT, long unsigned);
/* p = x + c ; return (p/10000 << 16 | p%10000) */

#define _carry_out_b65536(c) (c)

extern unsigned long _carry_out_b10000(unsigned long);
/* p = c ; return (p/10000 << 16 | p%10000) */

/*
 * Header file for revised "fast" base conversion based upon table look-up
 * methods.
 */

extern void
_big_float_times_power(_big_float *, int, int, int, _big_float **);

/* Variables defined in _small_powers.c and _big_powers.c	 */
/* Used in base conversion. */

/*
 * The run-time structure consists of two large tables of powers - either
 * powers of 10**4 in base 2**16 or vice versa.
 * 
 * Suppose it's powers of T in base B.  Then
 * 
 * _tiny_powers_T       contains TTINY entries, T**0, T**1, ... T**TTINY-1 where
 * T is 2 or 10, TTINY is 16 or 4 _small_powers_T      contains TSMALL
 * entries, T**0, T**1, ... T**TSMALL-1 where T is 2**TTINY or 10**TTINY
 * _big_powers_T        contains TBIG entries, T**0, T**1, ... T**TBIG-1
 * where T is (2**TTINY)**TSMALL or (10**TTINY)**TSMALL
 * 
 * so that any power of T from 0 to T**(TTINY*TSMALL*TBIG-1) can be represented
 * as a product of just two table entries.  Since the powers vary greatly in
 * size, the tables are condensed to exclude leading and trailing zeros.  The
 * following tables
 * 
 * _max_tiny_powers_T			contains one entry, TTINY
 * _start_tiny_powers_T                 contains TTINY entries
 * _leading_zeros_tiny_powers_T         contains TTINY entries
 * _max_small_powers_T			contains one entry, TSMALL
 * _start_small_powers_T                contains TSMALL entries
 * _leading_zeros_small_powers_T        contains TSMALL entries
 * _max_big_powers_T			contains one entry, TBIG
 * _start_big_powers_T                  contains TBIG entries
 * _leading_zeros_big_powers_T          contains TBIG entries
 * 
 * The powers are maintained with x[start] less significant than x[start+1], so
 * 
 * The powers are maintained with x[start] less significant than x[start+1], so
 * that the interpretation of a _small_powers_T entry is that
 * 
 * T**i = (B**leading_zeros[i]) * (x[start[i]] + x[start[i]+1] * B + ...
 * x[start[i+1]-1] * B**(start[i+1]-start[i]) )
 * 
 * where B = (2 or 10)**TTINY
 * 
 * The powers are listed consecutively in the tables, with start index and
 * leading zero information retained and printed out at the end.
 * 
 */

extern unsigned short _max_tiny_powers_ten;
extern unsigned short _tiny_powers_ten[];
extern unsigned short _start_tiny_powers_ten[];
extern unsigned short _leading_zeros_tiny_powers_ten[];
extern unsigned short _max_tiny_powers_two;
extern unsigned short _tiny_powers_two[];
extern unsigned short _start_tiny_powers_two[];

extern unsigned short _max_small_powers_ten;
extern unsigned short _small_powers_ten[];
extern unsigned short _start_small_powers_ten[];
extern unsigned short _leading_zeros_small_powers_ten[];
extern unsigned short _max_small_powers_two;
extern unsigned short _small_powers_two[];
extern unsigned short _start_small_powers_two[];

extern unsigned short _max_big_powers_ten;
extern unsigned short _big_powers_ten[];
extern unsigned short _start_big_powers_ten[];
extern unsigned short _leading_zeros_big_powers_ten[];
extern unsigned short _max_big_powers_two;
extern unsigned short _big_powers_two[];
extern unsigned short _start_big_powers_two[];

#endif /* _base_conversion_h */
