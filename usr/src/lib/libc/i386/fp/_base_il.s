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
	extern void _putsw(), _getsw();
	int sw;
	double z;

	_putsw(0);
	z = x * y;
	_getsw(&sw);
	if ((sw & 0x3f) == 0) {
		*pe = 0;
	} else {
		*pe = 1;
	}
	return (z);
}

 */
	ENTRY(__mul_set)
	subl	$0x8, %esp	/* Give us an extra 8 bytes to play with. */
	/* Clear the floating point exception register. */
	fnclex			/* Equivalent of _putsw(0); */
	
	fldl	0xc(%esp)	/* Load up x */
	fmull	0x14(%esp)	/* And multiply! */
	
	/* Check to see if the multiply caused any exceptions. */
	fstsw	(%esp)		/* Equivalent of... */
	xorl	%edx, %edx
	andl	$0x3f, (%esp)	/* If the status word (low bits) are zero... */
	setne	%dl		/* ... set *pe (aka. (%eax)) accordingly. */
	movl	0x1c(%esp), %eax/* Get pe. */
	movl	%edx, (%eax)	/* And set it.  (True == FP exception). */
	addl	$0x8, %esp	/* Release the 8 play bytes. */
	ret
	SET_SIZE(__mul_set)

/*
 * Divides two normal or subnormal doubles x/y, returns result and exceptions.
 *

double
__div_set(double x, double y, int *pe) {
	extern void _putsw(), _getsw();
	int sw;
	double z;

	_putsw(0);
	z = x / y;
	_getsw(&sw);
	if ((sw & 0x3f) == 0) {
		*pe = 0;
	} else {
		*pe = 1;
	}
	return (z);
}

 */
	
	ENTRY(__div_set)
	subl	$0x8, %esp	/* Give us an extra 8 bytes to play with. */
	/* Clear the floating point exception register. */
	fnclex			/* Equivalent of _putsw(0); */
	
	fldl	0xc(%esp)	/* Load up x */
	fdivl	0x14(%esp)	/* And divide! */
	
	/* Check to see if the divide caused any exceptions. */
	fstsw	(%esp)		/* Equivalent of... */
	xorl	%edx, %edx
	andl	$0x3f, (%esp)	/* If the status word (low bits) are zero... */
	setne	%dl		/* ... set *pe (aka. (%eax)) accordingly. */
	movl	0x1c(%esp), %eax/* Get pe. */
	movl	%edx, (%eax)	/* And set it.  (True == FP exception). */
	addl	$0x8, %esp	/* Release the 8 play bytes. */
	ret
	SET_SIZE(__div_set)

/* double __dabs(double *d) - Get the abs. value of *d.  Straightforward. */

	ENTRY(__dabs)
	movl	0x4(%esp), %eax
	fldl	(%eax)
	fabs			/* Just let the FPU do its thing. */
	ret
	SET_SIZE(__dabs)
