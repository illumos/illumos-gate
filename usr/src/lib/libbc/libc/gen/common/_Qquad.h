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
 * Copyright 1989 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _QUAD_INCLUDED_
#define	_QUAD_INCLUDED_		/* Render harmless multiple inclusions. */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

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

extern QUAD _Q_neg(QUAD);		/* returns -x */
extern QUAD _Q_add(QUAD, QUAD);		/* returns x + y */
extern QUAD _Q_sub(QUAD, QUAD);		/* returns x - y */
extern QUAD _Q_mul(QUAD, QUAD);		/* returns x * y */
extern QUAD _Q_div(QUAD, QUAD);		/* returns x / y */
extern QUAD _Q_sqrt(QUAD);		/* return sqrt(x) */
extern enum fcc_type
	_Q_cmp(QUAD, QUAD);		/* x compare y , exception */
					/* only on signaling NaN */
extern enum fcc_type
	_Q_cmpe(QUAD, QUAD);		/* x compare y , exception */
					/* on quiet NaN */
extern int   _Q_feq(QUAD, QUAD);	/* return TRUE if x == y */
extern int   _Q_fne(QUAD, QUAD);	/* return TRUE if x != y */
extern int   _Q_fgt(QUAD, QUAD);	/* return TRUE if x >  y */
extern int   _Q_fge(QUAD, QUAD);	/* return TRUE if x >= y */
extern int   _Q_flt(QUAD, QUAD);	/* return TRUE if x <  y */
extern int   _Q_fle(QUAD, QUAD);	/* return TRUE if x <= y */

/* Conversion routines are pretty straightforward. */

extern QUAD _Q_stoq(SINGLE);
extern QUAD _Q_dtoq(double);
extern QUAD _Q_itoq(int);
extern QUAD _Q_utoq(unsigned);
extern SINGLERESULT	_Q_qtos(QUAD);
extern double		_Q_qtod(QUAD);
extern int		_Q_qtoi(QUAD);
extern unsigned		_Q_qtou(QUAD);

/******	
    Phase I Quad support: scanf/printf support in libc/gen/common
*****/

enum fcc_type 	 		/* relationships for loading into cc */
	{
	fcc_equal	= 0,
	fcc_less	= 1,
	fcc_greater	= 2,
	fcc_unordered	= 3
	} ;

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

enum fp_op_type		/* Type specifiers in FPU instructions. */
	{
	fp_op_integer	= 0,	/* Not in hardware, but convenient to define. */
	fp_op_single	= 1,
	fp_op_double	= 2,
	fp_op_extended	= 3
	} ;


extern void	_Q_get_rp_rd(void);
extern void	_Q_set_exception(unsigned);

#endif				/* QUAD_INCLUDED */
