/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
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
 * Copyright 2011 Nexenta Systems, Inc.  All rights reserved.
 */
/*
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

	.file	"__vsqrtf.S"

#include "libm.h"

	ENTRY(__vsqrtf)
	push	%rbp
	movq	%rsp,%rbp

/ on entry:
/   %edi = n
/   %rsi = x
/   %edx = stridex
/   %rcx = y
/   %r8d = stridey

	movslq	%edx,%rdx		/ sign extend and scale strides
	shlq	$2,%rdx
	movslq	%r8d,%r8
	shlq	$2,%r8

	cmpl	$4,%edi
	jl	.finish

	cmpq	$4,%rdx
	jne	.nonunit
	cmpq	$4,%r8
	jne	.nonunit

/ unit-stride case
	movq	%rdx,%r9
	shlq	$2,%r9
	movq	%r8,%r10
	shlq	$2,%r10

	.align	16
.loop:
	movups	(%rsi),%xmm0
	addq	%r9,%rsi
	sqrtps	%xmm0,%xmm0
	movups	%xmm0,(%rcx)
	addq	%r10,%rcx
	subl	$4,%edi
	cmpl	$4,%edi
	jge	.loop

.finish:
	testl	%edi,%edi
	jle	.done

.finish_loop:
	movss	(%rsi),%xmm0
	addq	%rdx,%rsi
	sqrtss	%xmm0,%xmm0
	movss	%xmm0,(%rcx)
	addq	%r8,%rcx
	decl	%edi
	jg	.finish_loop

.done:
	leave
	ret

	.align	16
.nonunit:
	movss	(%rsi),%xmm0
	addq	%rdx,%rsi
	movss	(%rsi),%xmm1
	addq	%rdx,%rsi
	movss	(%rsi),%xmm2
	addq	%rdx,%rsi
	movss	(%rsi),%xmm3
	addq	%rdx,%rsi

	movlhps	%xmm1,%xmm0		/ xmm0:   0  x1   0  x0
	movlhps	%xmm3,%xmm2		/ xmm2:   0  x3   0  x2
	shufps	$0x88,%xmm2,%xmm0	/ xmm0:  x3  x2  x1  x0

	sqrtps	%xmm0,%xmm0		/ xmm0:  y3  y2  y1  y0

	movaps	%xmm0,%xmm1		/ xmm1:  y3  y2  y1  y0
	shufps	$0xf5,%xmm0,%xmm1	/ xmm1:  y3  y3  y1  y1
	movhlps	%xmm0,%xmm2		/ xmm2:   0  x3  y3  y2
	movhlps	%xmm1,%xmm3		/ xmm3:   0   0  y3  y3

	movss	%xmm0,(%rcx)
	addq	%r8,%rcx
	movss	%xmm1,(%rcx)
	addq	%r8,%rcx
	movss	%xmm2,(%rcx)
	addq	%r8,%rcx
	movss	%xmm3,(%rcx)
	addq	%r8,%rcx

	subl	$4,%edi
	cmpl	$4,%edi
	jge	.nonunit

	jmp	.finish

	SET_SIZE(__vsqrtf)
