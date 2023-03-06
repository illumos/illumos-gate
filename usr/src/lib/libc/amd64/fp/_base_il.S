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
 * Copyright 2014 OmniTI Computer Consulting, Inc. All rights reserved.
 */

	.file	"_base_il.s"

/*
 * These files are in assembly because some compilers will mistakenly reorder
 * multiplications or divisions wrapped in _putsw() and _getsw().  They are
 * proper subroutines for now, but should be considered candidates for
 * inlining eventually.
 *
 * The original C sources are included for readability in the pre-function
 * comment blocks.
 */

#include <SYS.h>

/*
 * Multiplies two normal or subnormal doubles, returns result and exceptions.
 *

double
__mul_set(double x, double y, int *pe) {
	extern void _putmxcsr(), _getmxcsr();
	int csr;
	double z;

	_putmxcsr(CSR_DEFAULT);
	z = x * y;
	_getmxcsr(&csr);
	if ((csr & 0x3f) == 0) {
		*pe = 0;
	} else {
		*pe = 1;
	}
	return (z);
}

 */
	ENTRY(__mul_set)
	xorl	%eax, %eax	/* Zero-out eax for later... */
	subq	$0x4, %rsp
	movl	$0x1f80, (%rsp)	/* 0x1f80 == CSR_DEFAULT. */
	/* Set the MXCSR to its default (i.e. No FP exceptions). */
	ldmxcsr	(%rsp)	/* Essentially _putmxcsr(CSR_DEFAULT); */
	
	mulsd	%xmm1, %xmm0	/* Do the multiply. */
	
	/* Check to see if the multiply caused any exceptions. */
	stmxcsr	(%rsp)	/* Essentially do _getmxcsr(). */
	andl	$0x3f, (%rsp)	/* Check it. */
	setne	%al		/* Boolean FP exception indicator for *pe. */
	movl	%eax, (%rdi)
	addq	$0x4, %rsp
	ret
	SET_SIZE(__mul_set)

/*
 * Divides two normal or subnormal doubles x/y, returns result and exceptions.
 *

double
__div_set(double x, double y, int *pe) {
	extern void _putmxcsr(), _getmxcsr();
	int csr;
	double z;

	_putmxcsr(CSR_DEFAULT);
	z = x / y;
	_getmxcsr(&csr);
	if ((csr & 0x3f) == 0) {
		*pe = 0;
	} else {
		*pe = 1;
	}
	return (z);
}

 */
	
	ENTRY(__div_set)
	xorl	%eax, %eax	/* Zero-out eax for later... */
	subq	$0x4, %rsp
	movl	$0x1f80, (%rsp)	/* 0x1f80 == CSR_DEFAULT. */
	/* Set the MXCSR to its default (i.e. No FP exceptions). */
	ldmxcsr	(%rsp)	/* Essentially _putmxcsr(CSR_DEFAULT); */
	
	divsd	%xmm1, %xmm0	/* Do the divide. */
	
	/* Check to see if the divide caused any exceptions. */
	stmxcsr	(%rsp)	/* Essentially do _getmxcsr(). */
	andl	$0x3f, (%rsp)	/* Check it. */
	setne	%al		/* Boolean FP exception indicator for *pe. */
	movl	%eax, (%rdi)
	addq	$0x4, %rsp
	ret
	SET_SIZE(__div_set)

/* double __dabs(double *d) - Get the abs. value of *d.  Straightforward. */

	ENTRY(__dabs)
	subq	$0x8, %rsp
	movq	(%rdi), %rax	/* Zero the sign bit of the 64-bit double. */
	btrq	$63, %rax
	movq	%rax, (%rsp)	/* Get it into %xmm0... */
	movsd   (%rsp), %xmm0	/* ....for an amd64 "double" return. */
	addq	$0x8, %rsp
	ret
	SET_SIZE(__dabs)
