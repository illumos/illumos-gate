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
/*	Copyright (C) 1989 AT&T	*/
/*	  All Rights Reserved */

/*
 * Copyright 2011 Nexenta Systems, Inc.  All rights reserved.
 */
/*
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _FLOATINGPOINT_H
#define	_FLOATINGPOINT_H

#ifdef __STDC__
#include <stdio_tag.h>
#endif
#include <sys/ieeefp.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * <floatingpoint.h> contains definitions for constants, types, variables,
 * and functions for:
 *	IEEE floating-point arithmetic base conversion;
 *	IEEE floating-point arithmetic modes;
 *	IEEE floating-point arithmetic exception handling.
 */

#ifndef __P
#ifdef __STDC__
#define	__P(p)	p
#else
#define	__P(p)	()
#endif
#endif	/* !defined(__P) */

#if defined(__STDC__) && !defined(_FILEDEFED)
#define	_FILEDEFED
typedef	__FILE FILE;
#endif

#define	N_IEEE_EXCEPTION 5	/* Number of floating-point exceptions. */

typedef int sigfpe_code_type;	/* Type of SIGFPE code. */

typedef void (*sigfpe_handler_type)();	/* Pointer to exception handler */

#define	SIGFPE_DEFAULT (void (*)())0	/* default exception handling */
#define	SIGFPE_IGNORE  (void (*)())1	/* ignore this exception or code */
#define	SIGFPE_ABORT   (void (*)())2	/* force abort on exception */

extern sigfpe_handler_type sigfpe __P((sigfpe_code_type, sigfpe_handler_type));

/*
 * Types for IEEE floating point.
 */
typedef float single;

#ifndef _EXTENDED
#define	_EXTENDED
typedef unsigned extended[3];
#endif

typedef long double quadruple;	/* Quadruple-precision type. */

typedef unsigned fp_exception_field_type;
				/*
				 * A field containing fp_exceptions OR'ed
				 * together.
				 */
/*
 * Definitions for base conversion.
 */
#define	DECIMAL_STRING_LENGTH 512	/* Size of buffer in decimal_record. */

typedef char decimal_string[DECIMAL_STRING_LENGTH];
				/* Decimal significand. */

typedef struct {
	enum fp_class_type fpclass;
	int	sign;
	int	exponent;
	decimal_string ds;	/* Significand - each char contains an ascii */
				/* digit, except the string-terminating */
				/* ascii null. */
	int	more;		/* On conversion from decimal to binary, != 0 */
				/* indicates more non-zero digits following */
				/* ds. */
	int	ndigits;	/* On fixed_form conversion from binary to */
				/* decimal, contains number of digits */
				/* required for ds. */
} decimal_record;

enum decimal_form {
	fixed_form,		/* Fortran F format: ndigits specifies number */
				/* of digits after point; if negative, */
				/* specifies rounding to occur to left of */
				/* point. */
	floating_form		/* Fortran E format: ndigits specifies number */
				/* of significant digits. */
};

typedef struct {
	enum fp_direction_type rd;
				/* Rounding direction. */
	enum decimal_form df;	/* Format for conversion from binary to */
				/* decimal. */
	int ndigits;		/* Number of digits for conversion. */
} decimal_mode;

enum decimal_string_form {	/* Valid decimal number string formats. */
	invalid_form,		/* Not a valid decimal string format. */
	whitespace_form,	/* All white space - valid in Fortran! */
	fixed_int_form,		/* <digs>		*/
	fixed_intdot_form,	/* <digs>.		*/
	fixed_dotfrac_form,	/* .<digs>		*/
	fixed_intdotfrac_form,	/* <digs>.<frac>	*/
	floating_int_form,	/* <digs><exp>		*/
	floating_intdot_form,	/* <digs>.<exp>		*/
	floating_dotfrac_form,	/* .<digs><exp>		*/
	floating_intdotfrac_form, /* <digs>.<digs><exp>	*/
	inf_form,		/* inf			*/
	infinity_form,		/* infinity		*/
	nan_form,		/* nan			*/
	nanstring_form		/* nan(string)		*/
};

extern void single_to_decimal __P((single *, decimal_mode *, decimal_record *,
				fp_exception_field_type *));
extern void double_to_decimal __P((double *, decimal_mode *, decimal_record *,
				fp_exception_field_type *));
extern void extended_to_decimal __P((extended *, decimal_mode *,
				decimal_record *, fp_exception_field_type *));
extern void quadruple_to_decimal __P((quadruple *, decimal_mode *,
				decimal_record *, fp_exception_field_type *));

extern void decimal_to_single __P((single *, decimal_mode *, decimal_record *,
				fp_exception_field_type *));
extern void decimal_to_double __P((double *, decimal_mode *, decimal_record *,
				fp_exception_field_type *));
extern void decimal_to_extended __P((extended *, decimal_mode *,
				decimal_record *, fp_exception_field_type *));
extern void decimal_to_quadruple __P((quadruple *, decimal_mode *,
				decimal_record *, fp_exception_field_type *));

extern void string_to_decimal __P((char **, int, int, decimal_record *,
				enum decimal_string_form *, char **));
extern void func_to_decimal __P((char **, int, int, decimal_record *,
				enum decimal_string_form *, char **,
				int (*)(void), int *, int (*)(int)));
extern void file_to_decimal __P((char **, int, int, decimal_record *,
				enum decimal_string_form *, char **,
				FILE *, int *));

extern char *seconvert __P((single *, int, int *, int *, char *));
extern char *sfconvert __P((single *, int, int *, int *, char *));
extern char *sgconvert __P((single *, int, int, char *));
extern char *econvert __P((double, int, int *, int *, char *));
extern char *fconvert __P((double, int, int *, int *, char *));
extern char *gconvert __P((double, int, int, char *));
extern char *qeconvert __P((quadruple *, int, int *, int *, char *));
extern char *qfconvert __P((quadruple *, int, int *, int *, char *));
extern char *qgconvert __P((quadruple *, int, int, char *));

extern char *ecvt __P((double, int, int *, int *));
extern char *fcvt __P((double, int, int *, int *));
extern char *gcvt __P((double, int, char *));

#if __cplusplus >= 199711L
namespace std {
#endif
/*
 * ANSI C Standard says the following entry points should be
 * prototyped in <stdlib.h>.  They are now, but weren't before.
 */
extern double atof __P((const char *));
extern double strtod __P((const char *, char **));
#if __cplusplus >= 199711L
}

using std::atof;
using std::strtod;
#endif /* end of namespace std */

#ifdef __cplusplus
}
#endif

#endif /* _FLOATINGPOINT_H */
