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
/
/ Copyright 2011 Nexenta Systems, Inc.  All rights reserved.
/
/ Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
/ Use is subject to license terms.
/

/ Portions of this file are duplicated as GCC inline assembly in
/ libm_inlines.h.  Keep them in sync.

	.inline	__ieee754_sqrt,0
	sqrtsd	%xmm0,%xmm0
	.end

	.inline	__inline_sqrtf,0
	sqrtss	%xmm0,%xmm0
	.end

	.inline	__inline_sqrt,0
	sqrtsd	%xmm0,%xmm0
	.end

/
/ 00 - 24 bits
/ 01 - reserved
/ 10 - 53 bits
/ 11 - 64 bits
/
	.inline	__swapRP,0
	subq	$16,%rsp
	fstcw	(%rsp)
	movw	(%rsp),%ax
	movw	%ax,%cx
	andw	$0xfcff,%cx
	andl	$0x3,%edi
	shlw	$8,%di
	orw	%di,%cx
	movl	%ecx,(%rsp)
	fldcw	(%rsp)
	shrw	$8,%ax
	andq	$0x3,%rax
	addq	$16,%rsp
	.end

/
/ 00 - Round to nearest, with even preferred
/ 01 - Round down
/ 10 - Round up
/ 11 - Chop
/
	.inline	__swap87RD,0
	subq	$16,%rsp
	fstcw	(%rsp)
	movw	(%rsp),%ax
	movw	%ax,%cx
	andw	$0xf3ff,%cx
	andl	$0x3,%edi
	shlw	$10,%di
	orw	%di,%cx
	movl	%ecx,(%rsp)
	fldcw	(%rsp)
	shrw	$10,%ax
	andq	$0x3,%rax
	addq	$16,%rsp
	.end

	.inline	abs,0
	cmpl	$0,%edi
	jge	1f
	negl	%edi
1:	movl	%edi,%eax
	.end

	.inline	copysign,0
	movq	$0x7fffffffffffffff,%rax
	movdq	%rax,%xmm2
	andpd	%xmm2,%xmm0
	andnpd	%xmm1,%xmm2
	orpd	%xmm2,%xmm0
	.end

	.inline	fabs,0
	movq	$0x7fffffffffffffff,%rax
	movdq	%rax,%xmm1
	andpd	%xmm1,%xmm0
	.end

	.inline	fabsf,0
	movl	$0x7fffffff,%eax
	movdl	%eax,%xmm1
	andps	%xmm1,%xmm0
	.end

	.inline	finite,0
	subq	$16,%rsp
	movlpd	%xmm0,(%rsp)
	movq	(%rsp),%rcx
	movq	$0x7fffffffffffffff,%rax
	andq	%rcx,%rax
	movq	$0x7ff0000000000000,%rcx
	subq	%rcx,%rax
	shrq	$63,%rax
	addq	$16,%rsp
	.end

	.inline	signbit,0
	movmskpd %xmm0,%eax
	andq	$1,%rax
	.end

	.inline	sqrt,0
	sqrtsd	%xmm0,%xmm0
	.end

	.inline	sqrtf,0
	sqrtss	%xmm0,%xmm0
	.end

	.inline	__f95_signf,0
	movl	(%rdi),%eax
	movl	(%rsi),%ecx
	andl	$0x7fffffff,%eax
	andl	$0x80000000,%ecx
	orl	%ecx,%eax
	movdl	%eax,%xmm0
	.end

	.inline	__f95_sign,0
	movq	(%rsi),%rax
	movq	$0x7fffffffffffffff,%rdx
	shrq	$63,%rax
	shlq	$63,%rax
	andq	(%rdi),%rdx
	orq	%rdx,%rax
	movdq	%rax,%xmm0
	.end

	.inline	__r_sign,0
	movl	$0x7fffffff,%eax
	movl	$0x80000000,%edx
	andl	(%rdi),%eax
	cmpl	(%rsi),%edx
	cmovel	%eax,%edx
	andl	(%rsi),%edx
	orl	%edx,%eax
	movdl	%eax,%xmm0
	.end

	.inline	__d_sign,0
	movq	$0x7fffffffffffffff,%rax
	movq	$0x8000000000000000,%rdx
	andq	(%rdi),%rax
	cmpq	(%rsi),%rdx
	cmoveq	%rax,%rdx
	andq	(%rsi),%rdx
	orq	%rdx,%rax
	movdq	%rax,%xmm0
	.end
