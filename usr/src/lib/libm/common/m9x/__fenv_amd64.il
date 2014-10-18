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
	fstsw	(%rdi)
	fstcw	2(%rdi)
	.end

	.inline	__fenv_setcwsw,1
	movw	(%rdi),%dx
	movw	2(%rdi),%cx
	subq	$32,%rsp
	fstenv	(%rsp)
	movw	%cx,(%rsp)
	movw	%dx,4(%rsp)
	fldenv	(%rsp)
	fwait
	addq	$32,%rsp
	.end

	.inline	__fenv_getmxcsr,1
	stmxcsr	(%rdi)
	.end

	.inline	__fenv_setmxcsr,1
	ldmxcsr	(%rdi)
	.end

	.inline	f2xm1,1
	fldt	(%rsp)
	f2xm1
	.end

	.inline	fyl2x,2
	fldt	(%rsp)
	fldt	16(%rsp)
	fyl2x
	.end

	.inline	fptan,1
	fldt	(%rsp)
	fptan
	fstpt	(%rsp)
	.end

	.inline	fpatan,2
	fldt	(%rsp)
	fldt	16(%rsp)
	fpatan
	.end

	.inline	fxtract,1
	fldt	(%rsp)
	fxtract
	.end

	.inline	fprem1,2
	fldt	(%rsp)
	fldt	16(%rsp)
	fprem1
	fstp	%st(1)
	.end

	.inline	fprem,2
	fldt	(%rsp)
	fldt	16(%rsp)
	fprem
	fstp	%st(1)
	.end

	.inline	fyl2xp1,2
	fldt	(%rsp)
	fldt	16(%rsp)
	fyl2xp1
	.end

	.inline	fsqrt,1
	fldt	(%rsp)
	fsqrt
	.end

	.inline	fsincos,1
	fldt	(%rsp)
	fsincos
	.end

	.inline	frndint,1
	fldt	(%rsp)
	frndint
	.end

	.inline	fscale,2
	fldt	(%rsp)
	fldt	16(%rsp)
	fscale
	fstp	%st(1)
	.end

	.inline	fsin,1
	fldt	(%rsp)
	fsin
	.end

	.inline	fcos,1
	fldt	(%rsp)
	fcos
	.end

	.inline	sse_cmpeqss,3
	movss	(%rdi),%xmm0
	cmpeqss	(%rsi),%xmm0
	movss	%xmm0,(%rdx)
	.end

	.inline	sse_cmpltss,3
	movss	(%rdi),%xmm0
	cmpltss	(%rsi),%xmm0
	movss	%xmm0,(%rdx)
	.end

	.inline	sse_cmpless,3
	movss	(%rdi),%xmm0
	cmpless	(%rsi),%xmm0
	movss	%xmm0,(%rdx)
	.end

	.inline	sse_cmpunordss,3
	movss	(%rdi),%xmm0
	cmpunordss	(%rsi),%xmm0
	movss	%xmm0,(%rdx)
	.end

	.inline	sse_minss,3
	movss	(%rdi),%xmm0
	minss	(%rsi),%xmm0
	movss	%xmm0,(%rdx)
	.end

	.inline	sse_maxss,3
	movss	(%rdi),%xmm0
	maxss	(%rsi),%xmm0
	movss	%xmm0,(%rdx)
	.end

	.inline	sse_addss,3
	movss	(%rdi),%xmm0
	addss	(%rsi),%xmm0
	movss	%xmm0,(%rdx)
	.end

	.inline	sse_subss,3
	movss	(%rdi),%xmm0
	subss	(%rsi),%xmm0
	movss	%xmm0,(%rdx)
	.end

	.inline	sse_mulss,3
	movss	(%rdi),%xmm0
	mulss	(%rsi),%xmm0
	movss	%xmm0,(%rdx)
	.end

	.inline	sse_divss,3
	movss	(%rdi),%xmm0
	divss	(%rsi),%xmm0
	movss	%xmm0,(%rdx)
	.end

	.inline	sse_sqrtss,2
	sqrtss	(%rdi),%xmm0
	movss	%xmm0,(%rsi)
	.end

	.inline	sse_ucomiss,2
	movss	(%rdi),%xmm0
	ucomiss	(%rsi),%xmm0
	.end

	.inline	sse_comiss,2
	movss	(%rdi),%xmm0
	comiss	(%rsi),%xmm0
	.end

	.inline	sse_cvtss2sd,2
	cvtss2sd	(%rdi),%xmm0
	movsd	%xmm0,(%rsi)
	.end

	.inline	sse_cvtsi2ss,2
	cvtsi2ss	(%rdi),%xmm0
	movss	%xmm0,(%rsi)
	.end

	.inline	sse_cvttss2si,2
	cvttss2si	(%rdi),%ecx
	movl	%ecx,(%rsi)
	.end

	.inline	sse_cvtss2si,2
	cvtss2si	(%rdi),%ecx
	movl	%ecx,(%rsi)
	.end

	.inline	sse_cvtsi2ssq,2
	cvtsi2ssq	(%rdi),%xmm0
	movss	%xmm0,(%rsi)
	.end

	.inline	sse_cvttss2siq,2
	cvttss2siq	(%rdi),%rcx
	movq	%rcx,(%rsi)
	.end

	.inline	sse_cvtss2siq,2
	cvtss2siq	(%rdi),%rcx
	movq	%rcx,(%rsi)
	.end

	.inline	sse_cmpeqsd,3
	movsd	(%rdi),%xmm0
	cmpeqsd	(%rsi),%xmm0
	movsd	%xmm0,(%rdx)
	.end

	.inline	sse_cmpltsd,3
	movsd	(%rdi),%xmm0
	cmpltsd	(%rsi),%xmm0
	movsd	%xmm0,(%rdx)
	.end

	.inline	sse_cmplesd,3
	movsd	(%rdi),%xmm0
	cmplesd	(%rsi),%xmm0
	movsd	%xmm0,(%rdx)
	.end

	.inline	sse_cmpunordsd,3
	movsd	(%rdi),%xmm0
	cmpunordsd	(%rsi),%xmm0
	movsd	%xmm0,(%rdx)
	.end

	.inline	sse_minsd,3
	movsd	(%rdi),%xmm0
	minsd	(%rsi),%xmm0
	movsd	%xmm0,(%rdx)
	.end

	.inline	sse_maxsd,3
	movsd	(%rdi),%xmm0
	maxsd	(%rsi),%xmm0
	movsd	%xmm0,(%rdx)
	.end

	.inline	sse_addsd,3
	movsd	(%rdi),%xmm0
	addsd	(%rsi),%xmm0
	movsd	%xmm0,(%rdx)
	.end

	.inline	sse_subsd,3
	movsd	(%rdi),%xmm0
	subsd	(%rsi),%xmm0
	movsd	%xmm0,(%rdx)
	.end

	.inline	sse_mulsd,3
	movsd	(%rdi),%xmm0
	mulsd	(%rsi),%xmm0
	movsd	%xmm0,(%rdx)
	.end

	.inline	sse_divsd,3
	movsd	(%rdi),%xmm0
	divsd	(%rsi),%xmm0
	movsd	%xmm0,(%rdx)
	.end

	.inline	sse_sqrtsd,2
	sqrtsd	(%rdi),%xmm0
	movsd	%xmm0,(%rsi)
	.end

	.inline	sse_ucomisd,2
	movsd	(%rdi),%xmm0
	ucomisd	(%rsi),%xmm0
	.end

	.inline	sse_comisd,2
	movsd	(%rdi),%xmm0
	comisd	(%rsi),%xmm0
	.end

	.inline	sse_cvtsd2ss,2
	cvtsd2ss	(%rdi),%xmm0
	movss	%xmm0,(%rsi)
	.end

	.inline	sse_cvtsi2sd,2
	cvtsi2sd	(%rdi),%xmm0
	movsd	%xmm0,(%rsi)
	.end

	.inline	sse_cvttsd2si,2
	cvttsd2si	(%rdi),%ecx
	movl	%ecx,(%rsi)
	.end

	.inline	sse_cvtsd2si,2
	cvtsd2si	(%rdi),%ecx
	movl	%ecx,(%rsi)
	.end

	.inline	sse_cvtsi2sdq,2
	cvtsi2sdq	(%rdi),%xmm0
	movsd	%xmm0,(%rsi)
	.end

	.inline	sse_cvttsd2siq,2
	cvttsd2siq	(%rdi),%rcx
	movq	%rcx,(%rsi)
	.end

	.inline	sse_cvtsd2siq,2
	cvtsd2siq	(%rdi),%rcx
	movq	%rcx,(%rsi)
	.end
