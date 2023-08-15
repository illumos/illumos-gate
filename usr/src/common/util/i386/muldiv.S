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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#if !defined(lint)
	.ident	"%Z%%M%	%I%	%E% SMI"

	.file	"muldiv.s"
#endif

#if defined(__i386) && !defined(__amd64)

/*
 * Helper routines for 32-bit compilers to perform 64-bit math.
 * These are used both by the Sun and GCC compilers.
 */

#include <sys/asm_linkage.h>
#include <sys/asm_misc.h>


#if defined(__lint)
#include <sys/types.h>

/* ARGSUSED */
int64_t
__mul64(int64_t a, int64_t b)
{
	return (0);
}

#else   /* __lint */

/
/   function __mul64(A,B:Longint):Longint;
/	{Overflow is not checked}
/
/ We essentially do multiply by longhand, using base 2**32 digits.
/               a       b	parameter A
/	     x 	c       d	parameter B
/		---------
/               ad      bd
/       ac	bc
/       -----------------
/       ac	ad+bc	bd
/
/       We can ignore ac and top 32 bits of ad+bc: if <> 0, overflow happened.
/
	ENTRY(__mul64)
	push	%ebp
	mov    	%esp,%ebp
	pushl	%esi
	mov	12(%ebp),%eax	/ A.hi (a)
	mull	16(%ebp)	/ Multiply A.hi by B.lo (produces ad)
	xchg	%ecx,%eax	/ ecx = bottom half of ad.
	movl    8(%ebp),%eax	/ A.Lo (b)
	movl	%eax,%esi	/ Save A.lo for later
	mull	16(%ebp)	/ Multiply A.Lo by B.LO (dx:ax = bd.)
	addl	%edx,%ecx	/ cx is ad
	xchg	%eax,%esi       / esi is bd, eax = A.lo (d)
	mull	20(%ebp)	/ Multiply A.lo * B.hi (producing bc)
	addl	%ecx,%eax	/ Produce ad+bc
	movl	%esi,%edx
	xchg	%eax,%edx
	popl	%esi
	movl	%ebp,%esp
	popl	%ebp
	ret     $16
	SET_SIZE(__mul64)

#endif	/* __lint */

/*
 * C support for 64-bit modulo and division.
 * Hand-customized compiler output - see comments for details.
 */
#if defined(__lint)

/* ARGSUSED */
uint64_t
__udiv64(uint64_t a, uint64_t b)
{ return (0); }

/* ARGSUSED */
uint64_t
__urem64(int64_t a, int64_t b)
{ return (0); }

/* ARGSUSED */
int64_t
__div64(int64_t a, int64_t b)
{ return (0); }

/* ARGSUSED */
int64_t
__rem64(int64_t a, int64_t b)
{ return (0); }

#else	/* __lint */

/ /*
/  * Unsigned division with remainder.
/  * Divide two uint64_ts, and calculate remainder.
/  */
/ uint64_t
/ UDivRem(uint64_t x, uint64_t y, uint64_t * pmod)
/ {
/ 	/* simple cases: y is a single uint32_t */
/ 	if (HI(y) == 0) {
/ 		uint32_t	div_hi, div_rem;
/ 		uint32_t 	q0, q1;
/
/ 		/* calculate q1 */
/ 		if (HI(x) < LO(y)) {
/ 			/* result is a single uint32_t, use one division */
/ 			q1 = 0;
/ 			div_hi = HI(x);
/ 		} else {
/ 			/* result is a double uint32_t, use two divisions */
/ 			A_DIV32(HI(x), 0, LO(y), q1, div_hi);
/ 		}
/
/ 		/* calculate q0 and remainder */
/ 		A_DIV32(LO(x), div_hi, LO(y), q0, div_rem);
/
/ 		/* return remainder */
/ 		*pmod = div_rem;
/
/ 		/* return result */
/ 		return (HILO(q1, q0));
/
/ 	} else if (HI(x) < HI(y)) {
/ 		/* HI(x) < HI(y) => x < y => result is 0 */
/
/ 		/* return remainder */
/ 		*pmod = x;
/
/ 		/* return result */
/ 		return (0);
/
/ 	} else {
/ 		/*
/ 		 * uint64_t by uint64_t division, resulting in a one-uint32_t
/ 		 * result
/ 		 */
/ 		uint32_t		y0, y1;
/ 		uint32_t		x1, x0;
/ 		uint32_t		q0;
/ 		uint32_t		normshift;
/
/ 		/* normalize by shifting x and y so MSB(y) == 1 */
/ 		HIBIT(HI(y), normshift);	/* index of highest 1 bit */
/ 		normshift = 31 - normshift;
/
/ 		if (normshift == 0) {
/ 			/* no shifting needed, and x < 2*y so q <= 1 */
/ 			y1 = HI(y);
/ 			y0 = LO(y);
/ 			x1 = HI(x);
/ 			x0 = LO(x);
/
/ 			/* if x >= y then q = 1 (note x1 >= y1) */
/ 			if (x1 > y1 || x0 >= y0) {
/ 				q0 = 1;
/ 				/* subtract y from x to get remainder */
/ 				A_SUB2(y0, y1, x0, x1);
/ 			} else {
/ 				q0 = 0;
/ 			}
/
/ 			/* return remainder */
/ 			*pmod = HILO(x1, x0);
/
/ 			/* return result */
/ 			return (q0);
/
/ 		} else {
/ 			/*
/ 			 * the last case: result is one uint32_t, but we need to
/ 			 * normalize
/ 			 */
/ 			uint64_t	dt;
/ 			uint32_t		t0, t1, x2;
/
/ 			/* normalize y */
/ 			dt = (y << normshift);
/ 			y1 = HI(dt);
/ 			y0 = LO(dt);
/
/ 			/* normalize x (we need 3 uint32_ts!!!) */
/ 			x2 = (HI(x) >> (32 - normshift));
/ 			dt = (x << normshift);
/ 			x1 = HI(dt);
/ 			x0 = LO(dt);
/
/ 			/* estimate q0, and reduce x to a two uint32_t value */
/ 			A_DIV32(x1, x2, y1, q0, x1);
/
/ 			/* adjust q0 down if too high */
/ 			/*
/ 			 * because of the limited range of x2 we can only be
/ 			 * one off
/ 			 */
/ 			A_MUL32(y0, q0, t0, t1);
/ 			if (t1 > x1 || (t1 == x1 && t0 > x0)) {
/ 				q0--;
/ 				A_SUB2(y0, y1, t0, t1);
/ 			}
/ 			/* return remainder */
/ 			/* subtract product from x to get remainder */
/ 			A_SUB2(t0, t1, x0, x1);
/ 			*pmod = (HILO(x1, x0) >> normshift);
/
/ 			/* return result */
/ 			return (q0);
/ 		}
/ 	}
/ }
	ENTRY(UDivRem)
	pushl	%ebp
	pushl	%edi
	pushl	%esi
	subl	$48, %esp
	movl	68(%esp), %edi	/ y,
	testl	%edi, %edi	/ tmp63
	movl	%eax, 40(%esp)	/ x, x
	movl	%edx, 44(%esp)	/ x, x
	movl	%edi, %esi	/, tmp62
	movl	%edi, %ecx	/ tmp62, tmp63
	jne	.LL2
	movl	%edx, %eax	/, tmp68
	cmpl	64(%esp), %eax	/ y, tmp68
	jae	.LL21
.LL4:
	movl	72(%esp), %ebp	/ pmod,
	xorl	%esi, %esi	/ <result>
	movl	40(%esp), %eax	/ x, q0
	movl	%ecx, %edi	/ <result>, <result>
	divl	64(%esp)	/ y
	movl	%edx, (%ebp)	/ div_rem,
	xorl	%edx, %edx	/ q0
	addl	%eax, %esi	/ q0, <result>
	movl	$0, 4(%ebp)
	adcl	%edx, %edi	/ q0, <result>
	addl	$48, %esp
	movl	%esi, %eax	/ <result>, <result>
	popl	%esi
	movl	%edi, %edx	/ <result>, <result>
	popl	%edi
	popl	%ebp
	ret
	.align	16
.LL2:
	movl	44(%esp), %eax	/ x,
	xorl	%edx, %edx
	cmpl	%esi, %eax	/ tmp62, tmp5
	movl	%eax, 32(%esp)	/ tmp5,
	movl	%edx, 36(%esp)
	jae	.LL6
	movl	72(%esp), %esi	/ pmod,
	movl	40(%esp), %ebp	/ x,
	movl	44(%esp), %ecx	/ x,
	movl	%ebp, (%esi)
	movl	%ecx, 4(%esi)
	xorl	%edi, %edi	/ <result>
	xorl	%esi, %esi	/ <result>
.LL22:
	addl	$48, %esp
	movl	%esi, %eax	/ <result>, <result>
	popl	%esi
	movl	%edi, %edx	/ <result>, <result>
	popl	%edi
	popl	%ebp
	ret
	.align	16
.LL21:
	movl	%edi, %edx	/ tmp63, div_hi
	divl	64(%esp)	/ y
	movl	%eax, %ecx	/, q1
	jmp	.LL4
	.align	16
.LL6:
	movl	$31, %edi	/, tmp87
	bsrl	%esi,%edx	/ tmp62, normshift
	subl	%edx, %edi	/ normshift, tmp87
	movl	%edi, 28(%esp)	/ tmp87,
	jne	.LL8
	movl	32(%esp), %edx	/, x1
	cmpl	%ecx, %edx	/ y1, x1
	movl	64(%esp), %edi	/ y, y0
	movl	40(%esp), %esi	/ x, x0
	ja	.LL10
	xorl	%ebp, %ebp	/ q0
	cmpl	%edi, %esi	/ y0, x0
	jb	.LL11
.LL10:
	movl	$1, %ebp	/, q0
	subl	%edi,%esi	/ y0, x0
	sbbl	%ecx,%edx	/ tmp63, x1
.LL11:
	movl	%edx, %ecx	/ x1, x1
	xorl	%edx, %edx	/ x1
	xorl	%edi, %edi	/ x0
	addl	%esi, %edx	/ x0, x1
	adcl	%edi, %ecx	/ x0, x1
	movl	72(%esp), %esi	/ pmod,
	movl	%edx, (%esi)	/ x1,
	movl	%ecx, 4(%esi)	/ x1,
	xorl	%edi, %edi	/ <result>
	movl	%ebp, %esi	/ q0, <result>
	jmp	.LL22
	.align	16
.LL8:
	movb	28(%esp), %cl
	movl	64(%esp), %esi	/ y, dt
	movl	68(%esp), %edi	/ y, dt
	shldl	%esi, %edi	/, dt, dt
	sall	%cl, %esi	/, dt
	andl	$32, %ecx
	jne	.LL23
.LL17:
	movl	$32, %ecx	/, tmp102
	subl	28(%esp), %ecx	/, tmp102
	movl	%esi, %ebp	/ dt, y0
	movl	32(%esp), %esi
	shrl	%cl, %esi	/ tmp102,
	movl	%edi, 24(%esp)	/ tmp99,
	movb	28(%esp), %cl
	movl	%esi, 12(%esp)	/, x2
	movl	44(%esp), %edi	/ x, dt
	movl	40(%esp), %esi	/ x, dt
	shldl	%esi, %edi	/, dt, dt
	sall	%cl, %esi	/, dt
	andl	$32, %ecx
	je	.LL18
	movl	%esi, %edi	/ dt, dt
	xorl	%esi, %esi	/ dt
.LL18:
	movl	%edi, %ecx	/ dt,
	movl	%edi, %eax	/ tmp2,
	movl	%ecx, (%esp)
	movl	12(%esp), %edx	/ x2,
	divl	24(%esp)
	movl	%edx, %ecx	/, x1
	xorl	%edi, %edi
	movl	%eax, 20(%esp)
	movl	%ebp, %eax	/ y0, t0
	mull	20(%esp)
	cmpl	%ecx, %edx	/ x1, t1
	movl	%edi, 4(%esp)
	ja	.LL14
	je	.LL24
.LL15:
	movl	%ecx, %edi	/ x1,
	subl	%eax,%esi	/ t0, x0
	sbbl	%edx,%edi	/ t1,
	movl	%edi, %eax	/, x1
	movl	%eax, %edx	/ x1, x1
	xorl	%eax, %eax	/ x1
	xorl	%ebp, %ebp	/ x0
	addl	%esi, %eax	/ x0, x1
	adcl	%ebp, %edx	/ x0, x1
	movb	28(%esp), %cl
	shrdl	%edx, %eax	/, x1, x1
	shrl	%cl, %edx	/, x1
	andl	$32, %ecx
	je	.LL16
	movl	%edx, %eax	/ x1, x1
	xorl	%edx, %edx	/ x1
.LL16:
	movl	72(%esp), %ecx	/ pmod,
	movl	20(%esp), %esi	/, <result>
	xorl	%edi, %edi	/ <result>
	movl	%eax, (%ecx)	/ x1,
	movl	%edx, 4(%ecx)	/ x1,
	jmp	.LL22
	.align	16
.LL24:
	cmpl	%esi, %eax	/ x0, t0
	jbe	.LL15
.LL14:
	decl	20(%esp)
	subl	%ebp,%eax	/ y0, t0
	sbbl	24(%esp),%edx	/, t1
	jmp	.LL15
.LL23:
	movl	%esi, %edi	/ dt, dt
	xorl	%esi, %esi	/ dt
	jmp	.LL17
	SET_SIZE(UDivRem)

/*
 * Unsigned division without remainder.
 */
/ uint64_t
/ UDiv(uint64_t x, uint64_t y)
/ {
/ 	if (HI(y) == 0) {
/ 		/* simple cases: y is a single uint32_t */
/ 		uint32_t	div_hi, div_rem;
/ 		uint32_t	q0, q1;
/
/ 		/* calculate q1 */
/ 		if (HI(x) < LO(y)) {
/ 			/* result is a single uint32_t, use one division */
/ 			q1 = 0;
/ 			div_hi = HI(x);
/ 		} else {
/ 			/* result is a double uint32_t, use two divisions */
/ 			A_DIV32(HI(x), 0, LO(y), q1, div_hi);
/ 		}
/
/ 		/* calculate q0 and remainder */
/ 		A_DIV32(LO(x), div_hi, LO(y), q0, div_rem);
/
/ 		/* return result */
/ 		return (HILO(q1, q0));
/
/ 	} else if (HI(x) < HI(y)) {
/ 		/* HI(x) < HI(y) => x < y => result is 0 */
/
/ 		/* return result */
/ 		return (0);
/
/ 	} else {
/ 		/*
/ 		 * uint64_t by uint64_t division, resulting in a one-uint32_t
/ 		 * result
/ 		 */
/ 		uint32_t		y0, y1;
/ 		uint32_t		x1, x0;
/ 		uint32_t		q0;
/ 		unsigned		normshift;
/
/ 		/* normalize by shifting x and y so MSB(y) == 1 */
/ 		HIBIT(HI(y), normshift);	/* index of highest 1 bit */
/ 		normshift = 31 - normshift;
/
/ 		if (normshift == 0) {
/ 			/* no shifting needed, and x < 2*y so q <= 1 */
/ 			y1 = HI(y);
/ 			y0 = LO(y);
/ 			x1 = HI(x);
/ 			x0 = LO(x);
/
/ 			/* if x >= y then q = 1 (note x1 >= y1) */
/ 			if (x1 > y1 || x0 >= y0) {
/ 				q0 = 1;
/ 				/* subtract y from x to get remainder */
/ 				/* A_SUB2(y0, y1, x0, x1); */
/ 			} else {
/ 				q0 = 0;
/ 			}
/
/ 			/* return result */
/ 			return (q0);
/
/ 		} else {
/ 			/*
/ 			 * the last case: result is one uint32_t, but we need to
/ 			 * normalize
/ 			 */
/ 			uint64_t	dt;
/ 			uint32_t		t0, t1, x2;
/
/ 			/* normalize y */
/ 			dt = (y << normshift);
/ 			y1 = HI(dt);
/ 			y0 = LO(dt);
/
/ 			/* normalize x (we need 3 uint32_ts!!!) */
/ 			x2 = (HI(x) >> (32 - normshift));
/ 			dt = (x << normshift);
/ 			x1 = HI(dt);
/ 			x0 = LO(dt);
/
/ 			/* estimate q0, and reduce x to a two uint32_t value */
/ 			A_DIV32(x1, x2, y1, q0, x1);
/
/ 			/* adjust q0 down if too high */
/ 			/*
/ 			 * because of the limited range of x2 we can only be
/ 			 * one off
/ 			 */
/ 			A_MUL32(y0, q0, t0, t1);
/ 			if (t1 > x1 || (t1 == x1 && t0 > x0)) {
/ 				q0--;
/ 			}
/ 			/* return result */
/ 			return (q0);
/ 		}
/ 	}
/ }
	ENTRY(UDiv)
	pushl	%ebp
	pushl	%edi
	pushl	%esi
	subl	$40, %esp
	movl	%edx, 36(%esp)	/ x, x
	movl	60(%esp), %edx	/ y,
	testl	%edx, %edx	/ tmp62
	movl	%eax, 32(%esp)	/ x, x
	movl	%edx, %ecx	/ tmp61, tmp62
	movl	%edx, %eax	/, tmp61
	jne	.LL26
	movl	36(%esp), %esi	/ x,
	cmpl	56(%esp), %esi	/ y, tmp67
	movl	%esi, %eax	/, tmp67
	movl	%esi, %edx	/ tmp67, div_hi
	jb	.LL28
	movl	%ecx, %edx	/ tmp62, div_hi
	divl	56(%esp)	/ y
	movl	%eax, %ecx	/, q1
.LL28:
	xorl	%esi, %esi	/ <result>
	movl	%ecx, %edi	/ <result>, <result>
	movl	32(%esp), %eax	/ x, q0
	xorl	%ecx, %ecx	/ q0
	divl	56(%esp)	/ y
	addl	%eax, %esi	/ q0, <result>
	adcl	%ecx, %edi	/ q0, <result>
.LL25:
	addl	$40, %esp
	movl	%esi, %eax	/ <result>, <result>
	popl	%esi
	movl	%edi, %edx	/ <result>, <result>
	popl	%edi
	popl	%ebp
	ret
	.align	16
.LL26:
	movl	36(%esp), %esi	/ x,
	xorl	%edi, %edi
	movl	%esi, 24(%esp)	/ tmp1,
	movl	%edi, 28(%esp)
	xorl	%esi, %esi	/ <result>
	xorl	%edi, %edi	/ <result>
	cmpl	%eax, 24(%esp)	/ tmp61,
	jb	.LL25
	bsrl	%eax,%ebp	/ tmp61, normshift
	movl	$31, %eax	/, tmp85
	subl	%ebp, %eax	/ normshift, normshift
	jne	.LL32
	movl	24(%esp), %eax	/, x1
	cmpl	%ecx, %eax	/ tmp62, x1
	movl	56(%esp), %esi	/ y, y0
	movl	32(%esp), %edx	/ x, x0
	ja	.LL34
	xorl	%eax, %eax	/ q0
	cmpl	%esi, %edx	/ y0, x0
	jb	.LL35
.LL34:
	movl	$1, %eax	/, q0
.LL35:
	movl	%eax, %esi	/ q0, <result>
	xorl	%edi, %edi	/ <result>
.LL45:
	addl	$40, %esp
	movl	%esi, %eax	/ <result>, <result>
	popl	%esi
	movl	%edi, %edx	/ <result>, <result>
	popl	%edi
	popl	%ebp
	ret
	.align	16
.LL32:
	movb	%al, %cl
	movl	56(%esp), %esi	/ y,
	movl	60(%esp), %edi	/ y,
	shldl	%esi, %edi
	sall	%cl, %esi
	andl	$32, %ecx
	jne	.LL43
.LL40:
	movl	$32, %ecx	/, tmp96
	subl	%eax, %ecx	/ normshift, tmp96
	movl	%edi, %edx
	movl	%edi, 20(%esp)	/, dt
	movl	24(%esp), %ebp	/, x2
	xorl	%edi, %edi
	shrl	%cl, %ebp	/ tmp96, x2
	movl	%esi, 16(%esp)	/, dt
	movb	%al, %cl
	movl	32(%esp), %esi	/ x, dt
	movl	%edi, 12(%esp)
	movl	36(%esp), %edi	/ x, dt
	shldl	%esi, %edi	/, dt, dt
	sall	%cl, %esi	/, dt
	andl	$32, %ecx
	movl	%edx, 8(%esp)
	je	.LL41
	movl	%esi, %edi	/ dt, dt
	xorl	%esi, %esi	/ dt
.LL41:
	xorl	%ecx, %ecx
	movl	%edi, %eax	/ tmp1,
	movl	%ebp, %edx	/ x2,
	divl	8(%esp)
	movl	%edx, %ebp	/, x1
	movl	%ecx, 4(%esp)
	movl	%eax, %ecx	/, q0
	movl	16(%esp), %eax	/ dt,
	mull	%ecx	/ q0
	cmpl	%ebp, %edx	/ x1, t1
	movl	%edi, (%esp)
	movl	%esi, %edi	/ dt, x0
	ja	.LL38
	je	.LL44
.LL39:
	movl	%ecx, %esi	/ q0, <result>
.LL46:
	xorl	%edi, %edi	/ <result>
	jmp	.LL45
.LL44:
	cmpl	%edi, %eax	/ x0, t0
	jbe	.LL39
.LL38:
	decl	%ecx		/ q0
	movl	%ecx, %esi	/ q0, <result>
	jmp	.LL46
.LL43:
	movl	%esi, %edi
	xorl	%esi, %esi
	jmp	.LL40
	SET_SIZE(UDiv)

/*
 * __udiv64
 *
 * Perform division of two unsigned 64-bit quantities, returning the
 * quotient in %edx:%eax.  __udiv64 pops the arguments on return,
 */
	ENTRY(__udiv64)
	movl	4(%esp), %eax	/ x, x
	movl	8(%esp), %edx	/ x, x
	pushl	16(%esp)	/ y
	pushl	16(%esp)
	call	UDiv
	addl	$8, %esp
	ret     $16
	SET_SIZE(__udiv64)

/*
 * __urem64
 *
 * Perform division of two unsigned 64-bit quantities, returning the
 * remainder in %edx:%eax.  __urem64 pops the arguments on return
 */
	ENTRY(__urem64)
	subl	$12, %esp
	movl	%esp, %ecx	/, tmp65
	movl	16(%esp), %eax	/ x, x
	movl	20(%esp), %edx	/ x, x
	pushl	%ecx		/ tmp65
	pushl	32(%esp)	/ y
	pushl	32(%esp)
	call	UDivRem
	movl	12(%esp), %eax	/ rem, rem
	movl	16(%esp), %edx	/ rem, rem
	addl	$24, %esp
	ret	$16
	SET_SIZE(__urem64)

/*
 * __div64
 *
 * Perform division of two signed 64-bit quantities, returning the
 * quotient in %edx:%eax.  __div64 pops the arguments on return.
 */
/ int64_t
/ __div64(int64_t x, int64_t y)
/ {
/ 	int		negative;
/ 	uint64_t	xt, yt, r;
/
/ 	if (x < 0) {
/ 		xt = -(uint64_t) x;
/ 		negative = 1;
/ 	} else {
/ 		xt = x;
/ 		negative = 0;
/ 	}
/ 	if (y < 0) {
/ 		yt = -(uint64_t) y;
/ 		negative ^= 1;
/ 	} else {
/ 		yt = y;
/ 	}
/ 	r = UDiv(xt, yt);
/ 	return (negative ? (int64_t) - r : r);
/ }
	ENTRY(__div64)
	pushl	%ebp
	pushl	%edi
	pushl	%esi
	subl	$8, %esp
	movl	28(%esp), %edx	/ x, x
	testl	%edx, %edx	/ x
	movl	24(%esp), %eax	/ x, x
	movl	32(%esp), %esi	/ y, y
	movl	36(%esp), %edi	/ y, y
	js	.LL84
	xorl	%ebp, %ebp	/ negative
	testl	%edi, %edi	/ y
	movl	%eax, (%esp)	/ x, xt
	movl	%edx, 4(%esp)	/ x, xt
	movl	%esi, %eax	/ y, yt
	movl	%edi, %edx	/ y, yt
	js	.LL85
.LL82:
	pushl	%edx		/ yt
	pushl	%eax		/ yt
	movl	8(%esp), %eax	/ xt, xt
	movl	12(%esp), %edx	/ xt, xt
	call	UDiv
	popl	%ecx
	testl	%ebp, %ebp	/ negative
	popl	%esi
	je	.LL83
	negl	%eax		/ r
	adcl	$0, %edx	/, r
	negl	%edx		/ r
.LL83:
	addl	$8, %esp
	popl	%esi
	popl	%edi
	popl	%ebp
	ret	$16
	.align	16
.LL84:
	negl	%eax		/ x
	adcl	$0, %edx	/, x
	negl	%edx		/ x
	testl	%edi, %edi	/ y
	movl	%eax, (%esp)	/ x, xt
	movl	%edx, 4(%esp)	/ x, xt
	movl	$1, %ebp	/, negative
	movl	%esi, %eax	/ y, yt
	movl	%edi, %edx	/ y, yt
	jns	.LL82
	.align	16
.LL85:
	negl	%eax		/ yt
	adcl	$0, %edx	/, yt
	negl	%edx		/ yt
	xorl	$1, %ebp	/, negative
	jmp	.LL82
	SET_SIZE(__div64)

/*
 * __rem64
 *
 * Perform division of two signed 64-bit quantities, returning the
 * remainder in %edx:%eax.  __rem64 pops the arguments on return.
 */
/ int64_t
/ __rem64(int64_t x, int64_t y)
/ {
/ 	uint64_t	xt, yt, rem;
/
/ 	if (x < 0) {
/ 		xt = -(uint64_t) x;
/ 	} else {
/ 		xt = x;
/ 	}
/ 	if (y < 0) {
/ 		yt = -(uint64_t) y;
/ 	} else {
/ 		yt = y;
/ 	}
/ 	(void) UDivRem(xt, yt, &rem);
/ 	return (x < 0 ? (int64_t) - rem : rem);
/ }
	ENTRY(__rem64)
	pushl	%edi
	pushl	%esi
	subl	$20, %esp
	movl	36(%esp), %ecx	/ x,
	movl	32(%esp), %esi	/ x,
	movl	36(%esp), %edi	/ x,
	testl	%ecx, %ecx
	movl	40(%esp), %eax	/ y, y
	movl	44(%esp), %edx	/ y, y
	movl	%esi, (%esp)	/, xt
	movl	%edi, 4(%esp)	/, xt
	js	.LL92
	testl	%edx, %edx	/ y
	movl	%eax, %esi	/ y, yt
	movl	%edx, %edi	/ y, yt
	js	.LL93
.LL90:
	leal	8(%esp), %eax	/, tmp66
	pushl	%eax		/ tmp66
	pushl	%edi		/ yt
	pushl	%esi		/ yt
	movl	12(%esp), %eax	/ xt, xt
	movl	16(%esp), %edx	/ xt, xt
	call	UDivRem
	addl	$12, %esp
	movl	36(%esp), %edi	/ x,
	testl	%edi, %edi
	movl	8(%esp), %eax	/ rem, rem
	movl	12(%esp), %edx	/ rem, rem
	js	.LL94
	addl	$20, %esp
	popl	%esi
	popl	%edi
	ret	$16
	.align	16
.LL92:
	negl	%esi
	adcl	$0, %edi
	negl	%edi
	testl	%edx, %edx	/ y
	movl	%esi, (%esp)	/, xt
	movl	%edi, 4(%esp)	/, xt
	movl	%eax, %esi	/ y, yt
	movl	%edx, %edi	/ y, yt
	jns	.LL90
	.align	16
.LL93:
	negl	%esi		/ yt
	adcl	$0, %edi	/, yt
	negl	%edi		/ yt
	jmp	.LL90
	.align	16
.LL94:
	negl	%eax		/ rem
	adcl	$0, %edx	/, rem
	addl	$20, %esp
	popl	%esi
	negl	%edx		/ rem
	popl	%edi
	ret	$16
	SET_SIZE(__rem64)

#endif	/* __lint */

#if defined(__lint)

/*
 * C support for 64-bit modulo and division.
 * GNU routines callable from C (though generated by the compiler).
 * Hand-customized compiler output - see comments for details.
 */
/*ARGSUSED*/
unsigned long long
__udivdi3(unsigned long long a, unsigned long long b)
{ return (0); }

/*ARGSUSED*/
unsigned long long
__umoddi3(unsigned long long a, unsigned long long b)
{ return (0); }

/*ARGSUSED*/
long long
__divdi3(long long a, long long b)
{ return (0); }

/*ARGSUSED*/
long long
__moddi3(long long a, long long b)
{ return (0); }

/* ARGSUSED */
int64_t __divrem64(int64_t a, int64_t b)
{ return (0); }

/* ARGSUSED */
uint64_t __udivrem64(uint64_t a, uint64_t b)
{ return (0); }

#else	/* __lint */

/*
 * int32_t/int64_t division/manipulation
 *
 * Hand-customized compiler output: the non-GCC entry points depart from
 * the SYS V ABI by requiring their arguments to be popped, and in the
 * [u]divrem64 cases returning the remainder in %ecx:%esi. Note the
 * compiler-generated use of %edx:%eax for the first argument of
 * internal entry points.
 *
 * Inlines for speed:
 * - counting the number of leading zeros in a word
 * - multiplying two 32-bit numbers giving a 64-bit result
 * - dividing a 64-bit number by a 32-bit number, giving both quotient
 *	and remainder
 * - subtracting two 64-bit results
 */
/ #define	LO(X)		((uint32_t)(X) & 0xffffffff)
/ #define	HI(X)		((uint32_t)((X) >> 32) & 0xffffffff)
/ #define	HILO(H, L)	(((uint64_t)(H) << 32) + (L))
/
/ /* give index of highest bit */
/ #define	HIBIT(a, r) \
/     asm("bsrl %1,%0": "=r"((uint32_t)(r)) : "g" (a))
/
/ /* multiply two uint32_ts resulting in a uint64_t */
/ #define	A_MUL32(a, b, lo, hi) \
/     asm("mull %2" \
/ 	: "=a"((uint32_t)(lo)), "=d"((uint32_t)(hi)) : "g" (b), "0"(a))
/
/ /* divide a uint64_t by a uint32_t */
/ #define	A_DIV32(lo, hi, b, q, r) \
/     asm("divl %2" \
/ 	: "=a"((uint32_t)(q)), "=d"((uint32_t)(r)) \
/ 	: "g" (b), "0"((uint32_t)(lo)), "1"((uint32_t)hi))
/
/ /* subtract two uint64_ts (with borrow) */
/ #define	A_SUB2(bl, bh, al, ah) \
/     asm("subl %4,%0\n\tsbbl %5,%1" \
/ 	: "=&r"((uint32_t)(al)), "=r"((uint32_t)(ah)) \
/ 	: "0"((uint32_t)(al)), "1"((uint32_t)(ah)), "g"((uint32_t)(bl)), \
/ 	"g"((uint32_t)(bh)))

/*
 * __udivdi3
 *
 * Perform division of two unsigned 64-bit quantities, returning the
 * quotient in %edx:%eax.
 */
	ENTRY(__udivdi3)
	movl	4(%esp), %eax	/ x, x
	movl	8(%esp), %edx	/ x, x
	pushl	16(%esp)	/ y
	pushl	16(%esp)
	call	UDiv
	addl	$8, %esp
	ret
	SET_SIZE(__udivdi3)

/*
 * __umoddi3
 *
 * Perform division of two unsigned 64-bit quantities, returning the
 * remainder in %edx:%eax.
 */
	ENTRY(__umoddi3)
	subl	$12, %esp
	movl	%esp, %ecx	/, tmp65
	movl	16(%esp), %eax	/ x, x
	movl	20(%esp), %edx	/ x, x
	pushl	%ecx		/ tmp65
	pushl	32(%esp)	/ y
	pushl	32(%esp)
	call	UDivRem
	movl	12(%esp), %eax	/ rem, rem
	movl	16(%esp), %edx	/ rem, rem
	addl	$24, %esp
	ret
	SET_SIZE(__umoddi3)

/*
 * __divdi3
 *
 * Perform division of two signed 64-bit quantities, returning the
 * quotient in %edx:%eax.
 */
/ int64_t
/ __divdi3(int64_t x, int64_t y)
/ {
/ 	int		negative;
/ 	uint64_t	xt, yt, r;
/
/ 	if (x < 0) {
/ 		xt = -(uint64_t) x;
/ 		negative = 1;
/ 	} else {
/ 		xt = x;
/ 		negative = 0;
/ 	}
/ 	if (y < 0) {
/ 		yt = -(uint64_t) y;
/ 		negative ^= 1;
/ 	} else {
/ 		yt = y;
/ 	}
/ 	r = UDiv(xt, yt);
/ 	return (negative ? (int64_t) - r : r);
/ }
	ENTRY(__divdi3)
	pushl	%ebp
	pushl	%edi
	pushl	%esi
	subl	$8, %esp
	movl	28(%esp), %edx	/ x, x
	testl	%edx, %edx	/ x
	movl	24(%esp), %eax	/ x, x
	movl	32(%esp), %esi	/ y, y
	movl	36(%esp), %edi	/ y, y
	js	.LL55
	xorl	%ebp, %ebp	/ negative
	testl	%edi, %edi	/ y
	movl	%eax, (%esp)	/ x, xt
	movl	%edx, 4(%esp)	/ x, xt
	movl	%esi, %eax	/ y, yt
	movl	%edi, %edx	/ y, yt
	js	.LL56
.LL53:
	pushl	%edx		/ yt
	pushl	%eax		/ yt
	movl	8(%esp), %eax	/ xt, xt
	movl	12(%esp), %edx	/ xt, xt
	call	UDiv
	popl	%ecx
	testl	%ebp, %ebp	/ negative
	popl	%esi
	je	.LL54
	negl	%eax		/ r
	adcl	$0, %edx	/, r
	negl	%edx		/ r
.LL54:
	addl	$8, %esp
	popl	%esi
	popl	%edi
	popl	%ebp
	ret
	.align	16
.LL55:
	negl	%eax		/ x
	adcl	$0, %edx	/, x
	negl	%edx		/ x
	testl	%edi, %edi	/ y
	movl	%eax, (%esp)	/ x, xt
	movl	%edx, 4(%esp)	/ x, xt
	movl	$1, %ebp	/, negative
	movl	%esi, %eax	/ y, yt
	movl	%edi, %edx	/ y, yt
	jns	.LL53
	.align	16
.LL56:
	negl	%eax		/ yt
	adcl	$0, %edx	/, yt
	negl	%edx		/ yt
	xorl	$1, %ebp	/, negative
	jmp	.LL53
	SET_SIZE(__divdi3)

/*
 * __moddi3
 *
 * Perform division of two signed 64-bit quantities, returning the
 * quotient in %edx:%eax.
 */
/ int64_t
/ __moddi3(int64_t x, int64_t y)
/ {
/ 	uint64_t	xt, yt, rem;
/
/ 	if (x < 0) {
/ 		xt = -(uint64_t) x;
/ 	} else {
/ 		xt = x;
/ 	}
/ 	if (y < 0) {
/ 		yt = -(uint64_t) y;
/ 	} else {
/ 		yt = y;
/ 	}
/ 	(void) UDivRem(xt, yt, &rem);
/ 	return (x < 0 ? (int64_t) - rem : rem);
/ }
	ENTRY(__moddi3)
	pushl	%edi
	pushl	%esi
	subl	$20, %esp
	movl	36(%esp), %ecx	/ x,
	movl	32(%esp), %esi	/ x,
	movl	36(%esp), %edi	/ x,
	testl	%ecx, %ecx
	movl	40(%esp), %eax	/ y, y
	movl	44(%esp), %edx	/ y, y
	movl	%esi, (%esp)	/, xt
	movl	%edi, 4(%esp)	/, xt
	js	.LL63
	testl	%edx, %edx	/ y
	movl	%eax, %esi	/ y, yt
	movl	%edx, %edi	/ y, yt
	js	.LL64
.LL61:
	leal	8(%esp), %eax	/, tmp66
	pushl	%eax		/ tmp66
	pushl	%edi		/ yt
	pushl	%esi		/ yt
	movl	12(%esp), %eax	/ xt, xt
	movl	16(%esp), %edx	/ xt, xt
	call	UDivRem
	addl	$12, %esp
	movl	36(%esp), %edi	/ x,
	testl	%edi, %edi
	movl	8(%esp), %eax	/ rem, rem
	movl	12(%esp), %edx	/ rem, rem
	js	.LL65
	addl	$20, %esp
	popl	%esi
	popl	%edi
	ret
	.align	16
.LL63:
	negl	%esi
	adcl	$0, %edi
	negl	%edi
	testl	%edx, %edx	/ y
	movl	%esi, (%esp)	/, xt
	movl	%edi, 4(%esp)	/, xt
	movl	%eax, %esi	/ y, yt
	movl	%edx, %edi	/ y, yt
	jns	.LL61
	.align	16
.LL64:
	negl	%esi		/ yt
	adcl	$0, %edi	/, yt
	negl	%edi		/ yt
	jmp	.LL61
	.align	16
.LL65:
	negl	%eax		/ rem
	adcl	$0, %edx	/, rem
	addl	$20, %esp
	popl	%esi
	negl	%edx		/ rem
	popl	%edi
	ret
	SET_SIZE(__moddi3)

/*
 * __udivrem64
 *
 * Perform division of two unsigned 64-bit quantities, returning the
 * quotient in %edx:%eax, and the remainder in %ecx:%esi.  __udivrem64
 * pops the arguments on return.
 */
	ENTRY(__udivrem64)
	subl	$12, %esp
	movl	%esp, %ecx	/, tmp64
	movl	16(%esp), %eax	/ x, x
	movl	20(%esp), %edx	/ x, x
	pushl	%ecx		/ tmp64
	pushl	32(%esp)	/ y
	pushl	32(%esp)
	call	UDivRem
	movl	16(%esp), %ecx	/ rem, tmp63
	movl	12(%esp), %esi	/ rem
	addl	$24, %esp
	ret	$16
	SET_SIZE(__udivrem64)

/*
 * Signed division with remainder.
 */
/ int64_t
/ SDivRem(int64_t x, int64_t y, int64_t * pmod)
/ {
/ 	int		negative;
/ 	uint64_t	xt, yt, r, rem;
/
/ 	if (x < 0) {
/ 		xt = -(uint64_t) x;
/ 		negative = 1;
/ 	} else {
/ 		xt = x;
/ 		negative = 0;
/ 	}
/ 	if (y < 0) {
/ 		yt = -(uint64_t) y;
/ 		negative ^= 1;
/ 	} else {
/ 		yt = y;
/ 	}
/ 	r = UDivRem(xt, yt, &rem);
/ 	*pmod = (x < 0 ? (int64_t) - rem : rem);
/ 	return (negative ? (int64_t) - r : r);
/ }
	ENTRY(SDivRem)
	pushl	%ebp
	pushl	%edi
	pushl	%esi
	subl	$24, %esp
	testl	%edx, %edx	/ x
	movl	%edx, %edi	/ x, x
	js	.LL73
	movl	44(%esp), %esi	/ y,
	xorl	%ebp, %ebp	/ negative
	testl	%esi, %esi
	movl	%edx, 12(%esp)	/ x, xt
	movl	%eax, 8(%esp)	/ x, xt
	movl	40(%esp), %edx	/ y, yt
	movl	44(%esp), %ecx	/ y, yt
	js	.LL74
.LL70:
	leal	16(%esp), %eax	/, tmp70
	pushl	%eax		/ tmp70
	pushl	%ecx		/ yt
	pushl	%edx		/ yt
	movl	20(%esp), %eax	/ xt, xt
	movl	24(%esp), %edx	/ xt, xt
	call	UDivRem
	movl	%edx, 16(%esp)	/, r
	movl	%eax, 12(%esp)	/, r
	addl	$12, %esp
	testl	%edi, %edi	/ x
	movl	16(%esp), %edx	/ rem, rem
	movl	20(%esp), %ecx	/ rem, rem
	js	.LL75
.LL71:
	movl	48(%esp), %edi	/ pmod, pmod
	testl	%ebp, %ebp	/ negative
	movl	%edx, (%edi)	/ rem,* pmod
	movl	%ecx, 4(%edi)	/ rem,
	movl	(%esp), %eax	/ r, r
	movl	4(%esp), %edx	/ r, r
	je	.LL72
	negl	%eax		/ r
	adcl	$0, %edx	/, r
	negl	%edx		/ r
.LL72:
	addl	$24, %esp
	popl	%esi
	popl	%edi
	popl	%ebp
	ret
	.align	16
.LL73:
	negl	%eax
	adcl	$0, %edx
	movl	44(%esp), %esi	/ y,
	negl	%edx
	testl	%esi, %esi
	movl	%edx, 12(%esp)	/, xt
	movl	%eax, 8(%esp)	/, xt
	movl	$1, %ebp	/, negative
	movl	40(%esp), %edx	/ y, yt
	movl	44(%esp), %ecx	/ y, yt
	jns	.LL70
	.align	16
.LL74:
	negl	%edx		/ yt
	adcl	$0, %ecx	/, yt
	negl	%ecx		/ yt
	xorl	$1, %ebp	/, negative
	jmp	.LL70
	.align	16
.LL75:
	negl	%edx		/ rem
	adcl	$0, %ecx	/, rem
	negl	%ecx		/ rem
	jmp	.LL71
	SET_SIZE(SDivRem)

/*
 * __divrem64
 *
 * Perform division of two signed 64-bit quantities, returning the
 * quotient in %edx:%eax, and the remainder in %ecx:%esi.  __divrem64
 * pops the arguments on return.
 */
	ENTRY(__divrem64)
	subl	$20, %esp
	movl	%esp, %ecx	/, tmp64
	movl	24(%esp), %eax	/ x, x
	movl	28(%esp), %edx	/ x, x
	pushl	%ecx		/ tmp64
	pushl	40(%esp)	/ y
	pushl	40(%esp)
	call	SDivRem
	movl	16(%esp), %ecx
	movl	12(%esp),%esi	/ rem
	addl	$32, %esp
	ret	$16
	SET_SIZE(__divrem64)


#endif /* __lint */

#endif /* defined(__i386) && !defined(__amd64) */
