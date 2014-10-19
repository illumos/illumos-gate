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
/ When distributing Covered Code, include this CDDL HEADER in each
/ file and include the License file at usr/src/OPENSOLARIS.LICENSE.
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
	.inline	__fenv_getcwsw,1
	movl	(%esp),%eax
	fstsw	(%eax)
	fstcw	2(%eax)
	.end

	.inline	__fenv_setcwsw,1
	movl	(%esp),%eax
	movw	(%eax),%dx
	movw	2(%eax),%cx
	subl	$28,%esp
	fstenv	(%esp)
	movw	%cx,(%esp)
	movw	%dx,4(%esp)
	fldenv	(%esp)
	fwait
	addl	$28,%esp
	.end

	.inline	__fenv_getmxcsr,1
	movl	(%esp),%eax
	stmxcsr	(%eax)
	.end

	.inline	__fenv_setmxcsr,1
	movl	(%esp),%eax
	ldmxcsr	(%eax)
	.end

	.inline	f2xm1,1
	fldt	(%esp)
	f2xm1
	.end

	.inline	fyl2x,2
	fldt	(%esp)
	fldt	12(%esp)
	fyl2x
	.end

	.inline	fptan,1
	fldt	(%esp)
	fptan
	fstpt	(%esp)
	.end

	.inline	fpatan,2
	fldt	(%esp)
	fldt	12(%esp)
	fpatan
	.end

	.inline	fxtract,1
	fldt	(%esp)
	fxtract
	.end

	.inline	fprem1,2
	fldt	(%esp)
	fldt	12(%esp)
	fprem1
	fstp	%st(1)
	.end

	.inline	fprem,2
	fldt	(%esp)
	fldt	12(%esp)
	fprem
	fstp	%st(1)
	.end

	.inline	fyl2xp1,2
	fldt	(%esp)
	fldt	12(%esp)
	fyl2xp1
	.end

	.inline	fsqrt,1
	fldt	(%esp)
	fsqrt
	.end

	.inline	fsincos,1
	fldt	(%esp)
	fsincos
	.end

	.inline	frndint,1
	fldt	(%esp)
	frndint
	.end

	.inline	fscale,2
	fldt	(%esp)
	fldt	12(%esp)
	fscale
	fstp	%st(1)
	.end

	.inline	fsin,1
	fldt	(%esp)
	fsin
	.end

	.inline	fcos,1
	fldt	(%esp)
	fcos
	.end

	.inline	sse_cmpeqss,3
	movl	(%esp),%eax
	movl	4(%esp),%edx
	movl	8(%esp),%ecx
	movss	(%eax),%xmm0
	cmpeqss	(%edx),%xmm0
	movss	%xmm0,(%ecx)
	.end

	.inline	sse_cmpltss,3
	movl	(%esp),%eax
	movl	4(%esp),%edx
	movl	8(%esp),%ecx
	movss	(%eax),%xmm0
	cmpltss	(%edx),%xmm0
	movss	%xmm0,(%ecx)
	.end

	.inline	sse_cmpless,3
	movl	(%esp),%eax
	movl	4(%esp),%edx
	movl	8(%esp),%ecx
	movss	(%eax),%xmm0
	cmpless	(%edx),%xmm0
	movss	%xmm0,(%ecx)
	.end

	.inline	sse_cmpunordss,3
	movl	(%esp),%eax
	movl	4(%esp),%edx
	movl	8(%esp),%ecx
	movss	(%eax),%xmm0
	cmpunordss	(%edx),%xmm0
	movss	%xmm0,(%ecx)
	.end

	.inline	sse_minss,3
	movl	(%esp),%eax
	movl	4(%esp),%edx
	movl	8(%esp),%ecx
	movss	(%eax),%xmm0
	minss	(%edx),%xmm0
	movss	%xmm0,(%ecx)
	.end

	.inline	sse_maxss,3
	movl	(%esp),%eax
	movl	4(%esp),%edx
	movl	8(%esp),%ecx
	movss	(%eax),%xmm0
	maxss	(%edx),%xmm0
	movss	%xmm0,(%ecx)
	.end

	.inline	sse_addss,3
	movl	(%esp),%eax
	movl	4(%esp),%edx
	movl	8(%esp),%ecx
	movss	(%eax),%xmm0
	addss	(%edx),%xmm0
	movss	%xmm0,(%ecx)
	.end

	.inline	sse_subss,3
	movl	(%esp),%eax
	movl	4(%esp),%edx
	movl	8(%esp),%ecx
	movss	(%eax),%xmm0
	subss	(%edx),%xmm0
	movss	%xmm0,(%ecx)
	.end

	.inline	sse_mulss,3
	movl	(%esp),%eax
	movl	4(%esp),%edx
	movl	8(%esp),%ecx
	movss	(%eax),%xmm0
	mulss	(%edx),%xmm0
	movss	%xmm0,(%ecx)
	.end

	.inline	sse_divss,3
	movl	(%esp),%eax
	movl	4(%esp),%edx
	movl	8(%esp),%ecx
	movss	(%eax),%xmm0
	divss	(%edx),%xmm0
	movss	%xmm0,(%ecx)
	.end

	.inline	sse_sqrtss,2
	movl	(%esp),%eax
	movl	4(%esp),%edx
	sqrtss	(%eax),%xmm0
	movss	%xmm0,(%edx)
	.end

	.inline	sse_ucomiss,2
	movl	(%esp),%eax
	movl	4(%esp),%edx
	movss	(%eax),%xmm0
	ucomiss	(%edx),%xmm0
	.end

	.inline	sse_comiss,2
	movl	(%esp),%eax
	movl	4(%esp),%edx
	movss	(%eax),%xmm0
	comiss	(%edx),%xmm0
	.end

	.inline	sse_cvtss2sd,2
	movl	(%esp),%eax
	movl	4(%esp),%edx
	cvtss2sd	(%eax),%xmm0
	movsd	%xmm0,(%edx)
	.end

	.inline	sse_cvtsi2ss,2
	movl	(%esp),%eax
	movl	4(%esp),%edx
	cvtsi2ss	(%eax),%xmm0
	movss	%xmm0,(%edx)
	.end

	.inline	sse_cvttss2si,2
	movl	(%esp),%eax
	movl	4(%esp),%edx
	cvttss2si	(%eax),%ecx
	movl	%ecx,(%edx)
	.end

	.inline	sse_cvtss2si,2
	movl	(%esp),%eax
	movl	4(%esp),%edx
	cvtss2si	(%eax),%ecx
	movl	%ecx,(%edx)
	.end

	.inline	sse_cmpeqsd,3
	movl	(%esp),%eax
	movl	4(%esp),%edx
	movl	8(%esp),%ecx
	movsd	(%eax),%xmm0
	cmpeqsd	(%edx),%xmm0
	movsd	%xmm0,(%ecx)
	.end

	.inline	sse_cmpltsd,3
	movl	(%esp),%eax
	movl	4(%esp),%edx
	movl	8(%esp),%ecx
	movsd	(%eax),%xmm0
	cmpltsd	(%edx),%xmm0
	movsd	%xmm0,(%ecx)
	.end

	.inline	sse_cmplesd,3
	movl	(%esp),%eax
	movl	4(%esp),%edx
	movl	8(%esp),%ecx
	movsd	(%eax),%xmm0
	cmplesd	(%edx),%xmm0
	movsd	%xmm0,(%ecx)
	.end

	.inline	sse_cmpunordsd,3
	movl	(%esp),%eax
	movl	4(%esp),%edx
	movl	8(%esp),%ecx
	movsd	(%eax),%xmm0
	cmpunordsd	(%edx),%xmm0
	movsd	%xmm0,(%ecx)
	.end

	.inline	sse_minsd,3
	movl	(%esp),%eax
	movl	4(%esp),%edx
	movl	8(%esp),%ecx
	movsd	(%eax),%xmm0
	minsd	(%edx),%xmm0
	movsd	%xmm0,(%ecx)
	.end

	.inline	sse_maxsd,3
	movl	(%esp),%eax
	movl	4(%esp),%edx
	movl	8(%esp),%ecx
	movsd	(%eax),%xmm0
	maxsd	(%edx),%xmm0
	movsd	%xmm0,(%ecx)
	.end

	.inline	sse_addsd,3
	movl	(%esp),%eax
	movl	4(%esp),%edx
	movl	8(%esp),%ecx
	movsd	(%eax),%xmm0
	addsd	(%edx),%xmm0
	movsd	%xmm0,(%ecx)
	.end

	.inline	sse_subsd,3
	movl	(%esp),%eax
	movl	4(%esp),%edx
	movl	8(%esp),%ecx
	movsd	(%eax),%xmm0
	subsd	(%edx),%xmm0
	movsd	%xmm0,(%ecx)
	.end

	.inline	sse_mulsd,3
	movl	(%esp),%eax
	movl	4(%esp),%edx
	movl	8(%esp),%ecx
	movsd	(%eax),%xmm0
	mulsd	(%edx),%xmm0
	movsd	%xmm0,(%ecx)
	.end

	.inline	sse_divsd,3
	movl	(%esp),%eax
	movl	4(%esp),%edx
	movl	8(%esp),%ecx
	movsd	(%eax),%xmm0
	divsd	(%edx),%xmm0
	movsd	%xmm0,(%ecx)
	.end

	.inline	sse_sqrtsd,2
	movl	(%esp),%eax
	movl	4(%esp),%edx
	sqrtsd	(%eax),%xmm0
	movsd	%xmm0,(%edx)
	.end

	.inline	sse_ucomisd,2
	movl	(%esp),%eax
	movl	4(%esp),%edx
	movsd	(%eax),%xmm0
	ucomisd	(%edx),%xmm0
	.end

	.inline	sse_comisd,2
	movl	(%esp),%eax
	movl	4(%esp),%edx
	movsd	(%eax),%xmm0
	comisd	(%edx),%xmm0
	.end

	.inline	sse_cvtsd2ss,2
	movl	(%esp),%eax
	movl	4(%esp),%edx
	cvtsd2ss	(%eax),%xmm0
	movss	%xmm0,(%edx)
	.end

	.inline	sse_cvtsi2sd,2
	movl	(%esp),%eax
	movl	4(%esp),%edx
	cvtsi2sd	(%eax),%xmm0
	movsd	%xmm0,(%edx)
	.end

	.inline	sse_cvttsd2si,2
	movl	(%esp),%eax
	movl	4(%esp),%edx
	cvttsd2si	(%eax),%ecx
	movl	%ecx,(%edx)
	.end

	.inline	sse_cvtsd2si,2
	movl	(%esp),%eax
	movl	4(%esp),%edx
	cvtsd2si	(%eax),%ecx
	movl	%ecx,(%edx)
	.end
