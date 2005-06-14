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
 * Copyright (c) 1989 by Sun Microsystems, Inc.
 */

/*
 * Header file for long double == quadruple-precision run-time support. C
 * "long double" and Fortran "real*16" are implemented identically on all
 * architectures.
 * 
 * Thus the quad run-time support is intentionally coded as C-callable routines
 * for portability.
 * 
 * Mixed-case identifiers with leading _ are intentionally chosen to minimize
 * conflicts with user-defined C and Fortran identifiers.
 */

#include <math.h>		/* to get float macros */

#ifndef _QUAD_INCLUDED_
#define _QUAD_INCLUDED_		/* Render harmless multiple inclusions. */


#ifdef __STDC__			/* are we there yet */

#define QUAD long double
#define SINGLE float
#define SINGLERESULT float
#define RETURNSINGLE(x) return x
#define ASSIGNSINGLERESULT(x,y) x = y

#else

struct quadstruct {
	unsigned        parts[4]
};

#define QUAD struct quadstruct

#define SINGLE FLOATPARAMETER
#define SINGLERESULT FLOATFUNCTIONTYPE
#define RETURNSINGLE(x) RETURNFLOAT(x)
#define ASSIGNSINGLERESULT(x,y) {SINGLERESULT _kug = y; *(int *)&x = *(int*)&_kug;}

#endif

/******		Phase I Quad support: C run-time in libc/crt		*****/

extern QUAD _Q_neg( /* QUAD x */ );	/* returns -x */
extern QUAD _Q_add( /* QUAD x, y */ );	/* returns x + y */
extern QUAD _Q_sub( /* QUAD x, y */ );	/* returns x - y */
extern QUAD _Q_mul( /* QUAD x, y */ );	/* returns x * y */
extern QUAD _Q_div( /* QUAD x, y */ );	/* returns x / y */
extern QUAD _Q_sqrt( /* QUAD x */ );	/* return sqrt(x) */
extern enum fcc_type
                _Q_cmp( /* QUAD x, y */ );	/* x compare y , exception
						 * only on signaling NaN */
extern enum fcc_type
                _Q_cmpe( /* QUAD x, y */ );	/* x compare y , exception
						 * on quiet NaN */
extern int   _Q_feq( /* QUAD x, y */ );	/* return TRUE if x == y */
extern int   _Q_fne( /* QUAD x, y */ );	/* return TRUE if x != y */
extern int   _Q_fgt( /* QUAD x, y */ );	/* return TRUE if x >  y */
extern int   _Q_fge( /* QUAD x, y */ );	/* return TRUE if x >= y */
extern int   _Q_flt( /* QUAD x, y */ );	/* return TRUE if x <  y */
extern int   _Q_fle( /* QUAD x, y */ );	/* return TRUE if x <= y */

/* Conversion routines are pretty straightforward. */

extern QUAD _Q_stoq( /* SINGLE s */ );
extern QUAD _Q_dtoq( /* double d */ );
extern QUAD _Q_itoq( /* int i */ );
extern QUAD _Q_utoq( /* unsigned u */ );
extern SINGLERESULT	_Q_qtos( /* QUAD x */ );
extern double		_Q_qtod( /* QUAD x */ );
extern int		_Q_qtoi( /* QUAD x */ );
extern unsigned		_Q_qtou( /* QUAD x */ );

/******	
    Phase I Quad support: scanf/printf support in libc/gen/common
*****/

extern void
decimal_to_longdouble(		/* QUAD *px ; decimal_mode *pm;
				 * decimal_record *pd;
		          fp_exception_field_type *ps; */ );

extern void
longdouble_to_decimal(		/* QUAD *px ; decimal_mode *pm;
				 * decimal_record *pd;
		          fp_exception_field_type *ps; */ );

#ifdef sparc
enum fcc_type 	 		/* relationships for loading into cc */
	{
	fcc_equal	= 0,
	fcc_less	= 1,
	fcc_greater	= 2,
	fcc_unordered	= 3
	} ;
#endif
#ifdef i386
enum fcc_type 	 		/* relationships for loading into cc */
	{
	fcc_equal	= 64,
	fcc_less	= 1,
	fcc_greater	= 0,
	fcc_unordered	= 69
	} ;
#endif
#ifdef mc68000
enum fcc_type 	 		/* relationships for loading into cc */
	{
	fcc_equal	= 4,
	fcc_less	= 25,
	fcc_greater	= 0,
	fcc_unordered	= 2
	} ;
#endif

#ifdef i386
typedef			/* FPU register viewed as single components. */
	struct
	{
	unsigned significand :	23 ;
	unsigned exponent :	 8 ;
	unsigned sign :		 1 ;
	}
	single_type ;

typedef			/* FPU register viewed as double components. */
	struct
	{
	unsigned significand :	20 ;
	unsigned exponent :	11 ;
	unsigned sign :		 1 ;
	}
	double_type ;
typedef			/* FPU register viewed as extended components. */
	struct
	{
	unsigned significand :	16 ;
	unsigned exponent :	15 ;
	unsigned sign :		 1 ;
	}
	extended_type ;
#else
typedef			/* FPU register viewed as single components. */
	struct
	{
	unsigned sign :		 1 ;
	unsigned exponent :	 8 ;
	unsigned significand :	23 ;
	}
	single_type ;

typedef			/* FPU register viewed as double components. */
	struct
	{
	unsigned sign :		 1 ;
	unsigned exponent :	11 ;
	unsigned significand :	20 ;
	}
	double_type ;
typedef			/* FPU register viewed as extended components. */
	struct
	{
	unsigned sign :		 1 ;
	unsigned exponent :	15 ;
	unsigned significand :	16 ;
	}
	extended_type ;
#endif


enum fp_op_type		/* Type specifiers in FPU instructions. */
	{
	fp_op_integer	= 0,	/* Not in hardware, but convenient to define. */
	fp_op_single	= 1,
	fp_op_double	= 2,
	fp_op_extended	= 3
	} ;


#endif				/* QUAD_INCLUDED */
