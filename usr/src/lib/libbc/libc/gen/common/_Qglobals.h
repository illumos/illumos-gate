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
 * Copyright 1988 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_qglobals_h
#define	_qglobals_h

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*	Sparc floating-point simulator PRIVATE include file. */

/*	PRIVATE CONSTANTS	*/
#define INTEGER_BIAS	   31
#define	SINGLE_BIAS	  127
#define DOUBLE_BIAS	 1023
#define EXTENDED_BIAS	16383

/* PRIVATE TYPES	*/
#ifdef DEBUG
#define PRIVATE
#else
#define PRIVATE static
#endif

typedef	struct {
	int sign ;
	enum fp_class_type fpclass ;
	int	exponent ;		/* Unbiased exponent. */
	unsigned significand[4] ;	/* Four significand word . */
	int	rounded;		/* rounded bit */
	int	sticky;			/* stick bit */
} unpacked ;

/* PRIVATE GLOBAL VARIABLES */

enum fp_direction_type fp_direction ;	/* Current rounding direction. */
enum fp_precision_type fp_precision ;	/* Current extended rounding precision. */

unsigned	_fp_current_exceptions ; /* Current floating-point exceptions. */

extern void _fp_unpack(unpacked *, int *, enum fp_op_type);
/*	unpacked	*pu ; */	/* unpacked result */
/*	int		*n ; */		/* register where data starts */
/*	fp_op_type	type ;*/	/* type of datum */

extern void _fp_pack(unpacked *, int *, enum fp_op_type);
/*	unpacked	*pu ; */	/* unpacked result */
/*	int		*n ; */		/* register where data starts */
/*	fp_op_type	type ; */	/* type of datum */

extern void fpu_normalize(unpacked *);
/*	unpacked	*pu ; */	/* unpacked operand and result */

extern void fpu_rightshift(unpacked *, int);
/*	unpacked *pu ; unsigned n ;	*/
/*	Right shift significand sticky by n bits. */

extern unsigned fpu_add3wc(unsigned *, unsigned, unsigned, unsigned);
/*	unsigned *z,x,y,c; */ 	/* *z = x+y+carry; return new carry */

extern unsigned fpu_sub3wc(unsigned *, unsigned, unsigned, unsigned);
/*	unsigned *z,x,y,c; */ 	/* *z = x-y-carry; return new carry */

extern unsigned fpu_neg2wc(unsigned *, unsigned, unsigned);
/*	unsigned *z,x,c; */ 	/* *z = 0-x-carry; return new carry */

extern int fpu_cmpli(unsigned [], unsigned [], int);
/*	unsigned x[],y[],n; */ 	/* n-word compare  */

extern void fpu_set_exception(enum fp_exception_type);
/*	enum fp_exception_type ex ; */	/* exception to be set in curexcep */

extern void fpu_error_nan(unpacked *);
/*	unpacked *pu ; */	/* Set invalid exception and error nan in *pu */

extern void unpacksingle(unpacked *, single_type);
/*	unpacked	*pu; */	/* packed result */
/*	single_type	x; */	/* packed single */

extern void unpackdouble(unpacked *, double_type, unsigned);
/*	unpacked	*pu; */	/* unpacked result */
/*	double_type	x; */	/* packed double */
/*	unsigned	y; */

extern enum fcc_type _fp_compare(unpacked *, unpacked *, int);

extern void _fp_add(unpacked *, unpacked *, unpacked *);
extern void _fp_sub(unpacked *, unpacked *, unpacked *);
extern void _fp_mul(unpacked *, unpacked *, unpacked *);
extern void _fp_div(unpacked *, unpacked *, unpacked *);
extern void _fp_sqrt(unpacked *, unpacked *);

#endif /* _qglobals_h */
