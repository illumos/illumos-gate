/
/ CDDL HEADER START
/
/ The contents of this file are subject to the terms of the
/ Common Development and Distribution License (the "License").
/ You may not use this file except in compliance with the License.
/
/ You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
/ or http://www.opensolaris.org/os/licensing.
/ See the License for the specific language governing permissions
/ and limitations under the License.
/
/ When distributing Covered Code,  this CDDL HEADER in each
/ file and  the License file at usr/src/OPENSOLARIS.LICENSE.
/ If applicable, add the following below this CDDL HEADER, with the
/ fields enclosed by brackets "[]" replaced with your own identifying
/ information: Portions Copyright [yyyy] [name of copyright owner]
/
/ CDDL HEADER END
/
/ Copyright 2011 Nexenta Systems, Inc.  All rights reserved.
/
/ Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
/ Use is subject to license terms.
/

/ Portions of this file are duplicated as GCC inline assembly in
/ libm_inlines.h.  Keep them in sync.

	.inline	__ieee754_sqrt,0
	fldl	(%esp)
	fsqrt
	.end

	.inline	__inline_rint,0
	fldl	(%esp)
        movl	4(%esp),%eax
        andl	$0x7fffffff,%eax
        cmpl	$0x43300000,%eax
        jae	1f
	frndint
1:
	fwait		/ in case we jumped around the frndint
	.end

	.inline	__inline_sqrtf,0
	flds	(%esp)
	fsqrt
	.end

	.inline	__inline_sqrt,0
	fldl	(%esp)
	fsqrt
	.end

	.inline	__inline_fstsw,0
	fstsw	%ax
	.end

/
/ 00 - 24 bits
/ 01 - reserved
/ 10 - 53 bits
/ 11 - 64 bits
/
	.inline	__swapRP,0
	subl	$4,%esp
	fstcw	(%esp)
	movw	(%esp),%ax
	movw	%ax,%cx
	andw	$0xfcff,%cx
	movl	4(%esp),%edx		///
	andl	$0x3,%edx
	shlw	$8,%dx
	orw	%dx,%cx
	movl	%ecx,(%esp)
	fldcw	(%esp)
	shrw	$8,%ax
	andl	$0x3,%eax
	addl	$4,%esp
	.end

/
/ 00 - Round to nearest, with even preferred
/ 01 - Round down
/ 10 - Round up
/ 11 - Chop
/
	.inline	__swap87RD,0
	subl	$4,%esp
	fstcw	(%esp)
	movw	(%esp),%ax
	movw	%ax,%cx
	andw	$0xf3ff,%cx
	movl	4(%esp),%edx
	andl	$0x3,%edx
	shlw	$10,%dx
	orw	%dx,%cx
	movl	%ecx,(%esp)
	fldcw	(%esp)
	shrw	$10,%ax
	andl	$0x3,%eax
	addl	$4,%esp
	.end

/
/	Convert Top-of-Stack to long
/
	.inline	__xtol,0
	subl	$8,%esp			/ 8 bytes of stack space
	fstcw	2(%esp)			/ byte[2:3] = old_cw
	movw	2(%esp),%ax
	andw	$0xf3ff,%ax
	orw	$0x0c00,%ax		/ RD set to Chop
	movw	%ax,(%esp)		/ byte[0:1] = new_cw
	fldcw	(%esp)			/ set new_cw
	fistpl	4(%esp)			/ byte[4:7] = converted long
	fstcw	(%esp)			/ restore old RD
	movw	(%esp),%ax
	andw	$0xf3ff,%ax
	movw	2(%esp),%dx
	andw	$0x0c00,%dx
	orw	%ax,%dx
	movw	%dx,2(%esp)
 	fldcw	2(%esp)
 	movl	4(%esp),%eax
	addl	$8,%esp
	.end

	.inline	ceil,0
	subl	$8,%esp
	fstcw	(%esp)
	fldl	8(%esp)			///
	movw	(%esp),%cx
	orw	$0x0c00,%cx
	xorw	$0x0400,%cx
	movw	%cx,4(%esp)
	fldcw	4(%esp)			/ set RD = up
	frndint
	fstcw	4(%esp)			/ restore RD
	movw	4(%esp),%dx
	andw	$0xf3ff,%dx
	movw	(%esp),%cx
	andw	$0x0c00,%cx
	orw	%dx,%cx
	movw	%cx,(%esp)
	fldcw	(%esp)
	addl	$8,%esp
	.end

	.inline	copysign,0
	movl	4(%esp),%eax		/// eax <-- hi_32(x)
	movl	12(%esp),%ecx		/// ecx <-- hi_32(y)
	andl	$0x7fffffff,%eax	/ eax <-- hi_32(abs(x))
	andl	$0x80000000,%ecx	/ ecx[31] <-- sign_bit(y)
	orl	%ecx,%eax		/ eax <-- hi_32(__copysign(x,y))
	movl	(%esp),%ecx		/// ecx <-- lo_32(x)
					/	= lo_32(__copysign(x,y))
	subl	$8,%esp			/ set up loading dock for result
	movl	%ecx,(%esp)		/ copy lo_32(result) to loading dock
	movl	%eax,4(%esp)		/ copy hi_32(result) to loading dock
	fldl	(%esp)			/ load __copysign(x,y)
	fwait				/ in case fldl causes exception
	addl	$8,%esp			/ restore stack-pointer
	.end

	.inline	__d_sqrt_,0
	movl	(%esp),%eax
	fldl	(%eax)
	fsqrt
	.end

	.inline	fabs,0
	fldl	(%esp)			///
	fabs
	.end

	.inline	fabsf,0
	flds	(%esp)
	fabs
	.end

	.inline	fabsl,0
	fldt	(%esp)
	fabs
	.end

/
/	branchless _finite
/
	.inline	finite,0
        movl    4(%esp),%eax		/// eax <-- hi_32(x)
        notl	%eax			/ not(bexp) = 0 iff bexp = all 1's
        andl    $0x7ff00000,%eax
	negl	%eax
	shrl	$31,%eax
        .end

	.inline	floor,0
	subl	$8,%esp
	fstcw	(%esp)
	fldl	8(%esp)			///
	movw	(%esp),%cx
	orw	$0x0c00,%cx
	xorw	$0x0800,%cx
	movw	%cx,4(%esp)
	fldcw	4(%esp)			/ set RD = down
	frndint
	fstcw	4(%esp)			/ restore RD
	movw	4(%esp),%dx
	andw	$0xf3ff,%dx
	movw	(%esp),%cx
	andw	$0x0c00,%cx
	orw	%dx,%cx
	movw	%cx,(%esp)
	fldcw	(%esp)			/ restore RD
	addl	$8,%esp
	.end

	.inline	isnanf,0
	movl	(%esp),%eax
	andl	$0x7fffffff,%eax
	negl	%eax
	addl	$0x7f800000,%eax
	shrl	$31,%eax
	.end


	.inline	__isnormal,0
					/ TRUE iff (x is _finite, but
					/           neither subnormal nor +/-0)
					/      iff (0 < bexp(x) < 0x7ff)
	movl	4(%esp),%eax		/ eax <-- hi_32(x)
	andl    $0x7ff00000,%eax        / eax[20..30]  <-- bexp(x),
					/ rest_of(eax) <-- 0
	pushfl
	popl    %ecx                    / bit 6 of ecx <-- not bexp(x)
	subl    $0x7ff00000,%eax
	pushfl
	popl    %eax                    / bit 6 of eax <-- not bexp(x)
	orl     %ecx,%eax
	andl    $0x40,%eax
	xorl    $0x40,%eax
	shrl    $6,%eax
	.end

	.inline	__issubnormal,0
					/ TRUE iff (bexp(x) = 0 and
					/	    frac(x) /= 0)
	movl    $0,%eax
        movl    4(%esp),%ecx            / ecx <-- hi_32(x)
	andl    $0x7fffffff,%ecx        / ecx <-- hi_32(abs(x))
	cmpl    $0x00100000,%ecx        / is bexp(x) = 0?
	adcl    $0,%eax                 / jump if bexp(x) = 0
	orl     (%esp),%ecx             / = 0 iff sgnfcnd(x) = 0
					/     iff x = +/- 0.0 here
	pushfl
	popl    %ecx
	andl    $0x40,%ecx
	xorl    $0x40,%ecx
	shrl    $6,%ecx
	andl    %ecx,%eax
	.end

	.inline	__iszero,0
	movl	4(%esp),%eax		/ eax <-- hi_32(x)
	andl    $0x7fffffff,%eax        / eax <-- hi_32(abs(x))
	orl     (%esp),%eax             / = 0 iff x = +/- 0.0
	pushfl
	popl    %eax
	andl    $0x40,%eax
	shrl    $6,%eax
	.end

	.inline	__r_sqrt_,0
	movl	(%esp),%eax
	flds	(%eax)
	fsqrt
	.end

	.inline	rint,0
	fldl	(%esp)
        movl	4(%esp),%eax
        andl	$0x7fffffff,%eax
        cmpl	$0x43300000,%eax
        jae	1f
	frndint
1:
	fwait			/ in case we jumped around frndint
	.end

	.inline	scalbn,0
	fildl	8(%esp)			/// convert N to extended
	fldl	(%esp)			/// push x
	fscale
	fstp	%st(1)
	.end

	.inline	signbit,0
	movl	4(%esp),%eax		/// high part of x
	shrl	$31,%eax
	.end

	.inline	signbitf,0
	movl	(%esp),%eax
	shrl	$31,%eax
	.end

	.inline	sqrt,0
	fldl	(%esp)
	fsqrt
	.end

	.inline	sqrtf,0
	flds	(%esp)
	fsqrt
	.end

	.inline	sqrtl,0
	fldt	(%esp)
	fsqrt
	.end

	.inline	isnanl,0
	movl    8(%esp),%eax            / ax <-- sign bit and __exp
	andl    $0x00007fff,%eax
	jz      1f                      / jump if __exp is all 0
	xorl    $0x00007fff,%eax
	jz      2f                      / jump if __exp is all 1
	testl   $0x80000000,4(%esp)
	jz      3f                      / jump if leading bit is 0
	movl    $0,%eax
	jmp     1f
2:                                      / note that %eax = 0 from before
	cmpl    $0x80000000,4(%esp)     / what is first half of __significand?
	jnz     3f                      / jump if not equal to 0x80000000
	testl   $0xffffffff,(%esp)      / is second half of __significand 0?
	jnz     3f                      / jump if not equal to 0
	jmp     1f
3:
	movl    $1,%eax
1:
	.end

	.inline	__f95_signf,0
	sub	$4,%esp
	mov	4(%esp),%edx
	mov	(%edx),%eax
	and	$0x7fffffff,%eax
	mov	8(%esp),%edx
	mov	(%edx),%ecx
	and	$0x80000000,%ecx
	or	%ecx,%eax
	mov	%eax,(%esp)
	flds	(%esp)
	add	$4,%esp
	.end

	.inline	__f95_sign,0
	mov	(%esp),%edx
	fldl	(%edx)
	fabs
	mov	4(%esp),%edx
	mov	4(%edx),%eax
	test	%eax,%eax
	jns	1f
	fchs
1:
	.end

