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
#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Copyright (c) 1988 by Sun Microsystems, Inc.
 */

/*
 * IEEE floating-point definitions for constants, types, variables, and
 * functions implemented in libc.a for: IEEE floating-point arithmetic base
 * conversion; IEEE floating-point arithmetic modes; IEEE floating-point
 * arithmetic exception handling; certain functions defined in 4.3 BSD and
 * System V.
 */

#ifndef _floatingpoint_h
#define _floatingpoint_h

#include <sys/ieeefp.h>

/* Sun TYPES for IEEE floating point.	 */

typedef float   single;
typedef unsigned long extended[3];	/* MC68881/i80387 double-extended type. */
#ifdef __STDC__
typedef long double quadruple;	/* Quadruple-precision type. */
#else
typedef struct {
	unsigned long   u[4];
}               quadruple;	/* Quadruple-precision type. */
#endif

#define N_IEEE_EXCEPTION 5	/* Number of floating-point exceptions. */

typedef unsigned fp_exception_field_type;
/*
 * A field containing fp_exceptions OR'ed together.
 */

typedef int     sigfpe_code_type;	/* Type of SIGFPE code. */

typedef void    (*sigfpe_handler_type) ();
/* Pointer to exception handler function. */

#define SIGFPE_DEFAULT	(void (*)())0	/* default exception handling */
#define SIGFPE_IGNORE	(void (*)())1	/* ignore this exception or code */
#define SIGFPE_ABORT	(void (*)())2	/* force abort on exception */

/* Sun VARIABLES for IEEE floating point. */

extern enum fp_direction_type fp_direction;
/*
 * Current rounding direction. Updated by ieee_flags.
 */

extern enum fp_precision_type fp_precision;
/*
 * Current rounding precision. Updated by ieee_flags.
 */

extern fp_exception_field_type fp_accrued_exceptions;
/*
 * Sticky accumulated exceptions, updated by ieee_flags. In hardware
 * implementations this variable is not automatically updated as the hardware
 * changes and should therefore not be relied on directly.
 */

/* Sun definitions for base conversion.			 */

#define DECIMAL_STRING_LENGTH 512
/* Size of buffer in decimal_record. */

typedef char    decimal_string[DECIMAL_STRING_LENGTH];
/* Decimal significand. */

typedef struct {
	enum fp_class_type fpclass;
	int             sign;
	int             exponent;
	decimal_string  ds;	/* Significand - each char contains an ascii
				 * digit, except the string-terminating ascii
				 * null. */
	int             more;	/* On conversion from decimal to binary, != 0
				 * indicates more non-zero digits following
				 * ds. */
	int             ndigits;/* On fixed_form conversion from binary to
				 * decimal, contains number of digits
				 * required for ds. */
}
                decimal_record;

enum decimal_form {
	fixed_form,		/* Fortran F format: ndigits specifies number
				 * of digits after point; if negative,
				 * specifies rounding to occur to left of
				 * point. */
	floating_form		/* Fortran E format: ndigits specifies number
				 * of significant digits. */
};

typedef struct {
	enum fp_direction_type rd;
	/* Rounding direction. */
	enum decimal_form df;	/* Format for binary to decimal conversion. */
	int             ndigits;/* Number of digits for conversion. */
}
                decimal_mode;

enum decimal_string_form {	/* Valid decimal number string formats. */
	invalid_form,		/* Not a valid decimal string format. */
	whitespace_form,	/* All white space - valid in Fortran! */
	fixed_int_form,		/* <digs> 		 */
	fixed_intdot_form,	/* <digs>. 		 */
	fixed_dotfrac_form,	/* .<digs>		 */
	fixed_intdotfrac_form,	/* <digs>.<frac>	 */
	floating_int_form,	/* <digs><exp>		 */
	floating_intdot_form,	/* <digs>.<exp>		 */
	floating_dotfrac_form,	/* .<digs><exp>		 */
	floating_intdotfrac_form,	/* <digs>.<digs><exp>	 */
	inf_form,		/* inf			 */
	infinity_form,		/* infinity		 */
	nan_form,		/* nan			 */
	nanstring_form		/* nan(string)		 */
};

/*	The following externs are used in the implementation of sprintf.		*/

extern void     double_to_decimal();
extern void     quadruple_to_decimal();
extern char    *econvert();
extern char    *fconvert();
extern char    *gconvert();
extern char    *qeconvert();
extern char    *qfconvert();
extern char    *qgconvert();

/*
	The following are used for other parts of base conversion.
*/

extern sigfpe_handler_type ieee_handlers[N_IEEE_EXCEPTION];
/*
 * Array of pointers to functions to handle SIGFPE's corresponding to IEEE
 * fp_exceptions. sigfpe_default means do not generate SIGFPE. An invalid
 * address such as sigfpe_abort will cause abort on that SIGFPE. Updated by
 * ieee_handler.
 */

extern sigfpe_handler_type sigfpe();

extern void     single_to_decimal();
extern void     extended_to_decimal();

extern void     decimal_to_single();
extern void     decimal_to_double();
extern void     decimal_to_extended();
extern void     decimal_to_quadruple();

extern char    *seconvert();
extern char    *sfconvert();
extern char    *sgconvert();

extern void     string_to_decimal();
extern void     file_to_decimal();
extern void     func_to_decimal();

/* Definitions from 4.3 BSD math.h  4.6  9/11/85		 */

extern double   atof();

/* Definitions from System V				 */

extern int      errno;

extern double   strtod();

#endif				/* !_floatingpoint_h */
