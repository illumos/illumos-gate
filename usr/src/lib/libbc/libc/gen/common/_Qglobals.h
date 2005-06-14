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

	/*	Sparc floating-point simulator PRIVATE include file. */

#ifdef KERNEL
#include <sys/types.h>
#include <vm/seg.h>
#endif

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

#ifdef KERNEL
#define	DOUBLE_E(n) (n & 0xfffe) /* More significant word of double. */
#define DOUBLE_F(n) (1+DOUBLE_E(n)) /* Less significant word of double. */
#define	EXTENDED_E(n) (n & 0xfffc) /* Sign/exponent/significand of extended. */
#define EXTENDED_F(n) (1+EXTENDED_E(n)) /* 2nd word of extended significand. */
#define EXTENDED_G(n) (2+EXTENDED_E(n)) /* 3rd word of extended significand. */
#define EXTENDED_H(n) (3+EXTENDED_E(n)) /* 4th word of extended significand. */
#endif

typedef
	struct
	{
	int sign ;
	enum fp_class_type fpclass ;
	int	exponent ;		/* Unbiased exponent. */
	unsigned significand[4] ;	/* Four significand word . */
	int	rounded;		/* rounded bit */
	int	sticky;			/* stick bit */
	}
	unpacked ;

	/* PRIVATE GLOBAL VARIABLES */

enum fp_direction_type fp_direction ;	/* Current rounding direction. */
enum fp_precision_type fp_precision ;	/* Current extended rounding precision. */

unsigned	_fp_current_exceptions ; /* Current floating-point exceptions. */

#ifdef KERNEL
struct fpu	* _fp_current_pfregs ;		/* Current pointer to stored f registers. */

void	(* _fp_current_read_freg) () ;	/* Routine to use to read f registers. */
void	(* _fp_current_write_freg) () ;	/* Routine to use to write f registers. */

int		fptrapcode ;		/* Last code for fp trap. */
char		*fptrapaddr ;		/* Last addr for fp trap. */
enum seg_rw	fptraprw ;		/* Last fp fault read/write flag */

	/* PRIVATE FUNCTIONS */

	/* pfreg routines use "physical" FPU registers. */

extern void _fp_read_pfreg ( /* pf, n */ ) ;

/*	FPU_REGS_TYPE *pf		/* Where to put current %fn. */
/*	unsigned n ;			/* Want to read register n. */

extern void _fp_write_pfreg ( /* pf, n */ ) ;

/*	FPU_REGS_TYPE *pf		/* Where to get new %fn. */
/*	unsigned n ;			/* Want to read register n. */

	/* vfreg routines use "virtual" FPU registers at *_fp_current_pfregs. */

extern void _fp_read_vfreg ( /* pf, n */ ) ;

/*	FPU_REGS_TYPE *pf		/* Where to put current %fn. */
/*	unsigned n ;			/* Want to read register n. */

extern void _fp_write_vfreg ( /* pf, n */ ) ;

/*	FPU_REGS_TYPE *pf		/* Where to get new %fn. */
/*	unsigned n ;			/* Want to read register n. */

extern enum ftt_type
_fp_iu_simulator( /* pinst, pregs, pwindow, pfpu */ ) ;
/*	fp_inst_type	pinst;	/* FPU instruction to simulate. */
/*	struct regs	*pregs;	/* Pointer to PCB image of registers. */
/*	struct window	*pwindow;/* Pointer to locals and ins. */
/*	struct fpu	*pfpu;	/* Pointer to FPU register block. */
#endif

extern void _fp_unpack ( /* pu, n, type */ ) ;
/*	unpacked	*pu ;	/* unpacked result */
/*	unsigned	n ;	/* register where data starts */
/*	fp_op_type	type ;	/* type of datum */

extern void _fp_pack ( /* pu, n, type */) ;
/*	unpacked	*pu ;	/* unpacked result */
/*	unsigned	n ;	/* register where data starts */
/*	fp_op_type	type ;	/* type of datum */

extern void _fp_unpack_word ( /* pu, n, type */ ) ;
/*	unsigned	*pu ;	/* unpacked result */
/*	unsigned	n ;	/* register where data starts */

extern void _fp_pack_word ( /* pu, n, type */) ;
/*	unsigned	*pu ;	/* unpacked result */
/*	unsigned	n ;	/* register where data starts */

extern void fpu_normalize (/* pu */) ;
/*	unpacked	*pu ;	/* unpacked operand and result */

extern void fpu_rightshift (/* pu, n */) ;
/*	unpacked *pu ; unsigned n ;	*/
/*	Right shift significand sticky by n bits. */

extern unsigned fpu_add3wc (/* z,x,y,c */) ;
/*	unsigned *z,x,y,c; 	/* *z = x+y+carry; return new carry */

extern unsigned fpu_sub3wc (/* z,x,y,c */) ;
/*	unsigned *z,x,y,c; 	/* *z = x-y-carry; return new carry */

extern unsigned fpu_neg2wc  (/* x,c */) ;
/*	unsigned *z,x,c; 	/* *z = 0-x-carry; return new carry */

extern int fpu_cmpli (/* x,y,n */) ;
/*	unsigned x[],y[],n; 	/* n-word compare  */

extern void fpu_set_exception(/* ex */) ;
/*	enum fp_exception_type ex ;	/* exception to be set in curexcep */

extern void fpu_error_nan(/* pu */) ;
/*	unpacked *pu ; 			/* Set invalid exception and error nan in *pu */

extern void unpacksingle (/* pu, x */) ;
/*	unpacked	*pu;	/* packed result */
/*	single_type	x;	/* packed single */

extern void unpackdouble (/* pu, x, y */) ;
/*	unpacked	*pu;	/* unpacked result */
/*	double_type	x;	/* packed double */
/*	unsigned	y;	*/

extern enum fcc_type _fp_compare (/* px, py */) ;

extern void _fp_add(/* px, py, pz */) ;
extern void _fp_sub(/* px, py, pz */) ;
extern void _fp_mul(/* px, py, pz */) ;
extern void _fp_div(/* px, py, pz */) ;
extern void _fp_sqrt(/* px, pz */) ;

#ifdef KERNEL
extern enum ftt_type	_fp_write_word ( /* caddr_t, value */ ) ;
extern enum ftt_type	_fp_read_word ( /* caddr_t, pvalue */ ) ;
extern enum ftt_type	read_iureg ( /* n, pregs, pwindow, pvalue */ );
#endif
