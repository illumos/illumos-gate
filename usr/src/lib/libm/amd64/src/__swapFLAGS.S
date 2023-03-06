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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

	.file	"__swapFLAGS.s"

#include "libm.h"

/*
 * swap exception masks
 *
 * Put the complement of bits 5-0 of the argument into FPCW bits 5-0
 * and MXCSR bits 12-7, return the complement of the previous FPCW
 * bits 5-0.
 */
	ENTRY(__swapTE)		/ di <-- NOT(desired xcptn_masks)
	subq	$8,%rsp
	fstcw	(%rsp)		/ push current_cw on '86 stack
	movq	(%rsp),%rcx	/ cx <-- current_cw
	movw	%cx,%ax		/ ax <-- current_cw
	orw	$0x3f,%cx	/ cx <-- current_cw, but masking all xcptns
	andw	$0x3f,%di	/ make sure bits > B5 are all zero
	xorw	%di,%cx		/ cx <-- present_cw, with new xcptn_masks
	movw	%cx,(%rsp)
	fldcw	(%rsp)		/ load new cw 
	stmxcsr	(%rsp)
	movq	(%rsp),%rcx
	orw	$0x1f80,%cx	/ cx <-- current mxcsr, but masking all xcptns
	shlw	$7,%di
	xorw	%di,%cx		/ cx <-- present mxcsr, with new xcptn_masks
	movq	%rcx,(%rsp)
	ldmxcsr	(%rsp)
	andq	$0x3f,%rax	/ al[5..0] <-- former xcptn_masks
	xorq	$0x3f,%rax	/ al[5..0] <-- NOT(former xcptn_masks)
	addq	$8,%rsp
	ret
	.align	16
	SET_SIZE(__swapTE)

/*
 * swap exception flags
 *
 * Put bits 5-0 of the argument into FPSW bits 5-0 and MXCSR bits 5-0,
 * return the "or" of the previous FPSW bits 5-0 and MXCSR bits 5-0.
 */
	ENTRY(__swapEX)
	fstsw	%ax		/ ax = sw
	andq	$0x3f,%rdi
	jnz	.L1
				/ input ex=0, clear all exception
	fnclex	
	subq	$8,%rsp
	stmxcsr	(%rsp)
	movq	(%rsp),%rcx
	orw	%cx,%ax
	andw	$0xffc0,%cx
	movq	%rcx,(%rsp)
	ldmxcsr	(%rsp)
	andq	$0x3f,%rax
	addq	$8,%rsp
	ret
.L1:
				/ input ex !=0, use fnstenv and fldenv
	subq	$32,%rsp	/ only needed 28
	fnstenv	(%rsp)
	movw	%ax,%dx
	andw	$0xffc0,%dx
	orw	%cx,%dx
	movw	%dx,4(%rsp)	/ replace old sw by new one
	fldenv	(%rsp)
	stmxcsr	(%rsp)
	movq	(%rsp),%rdx
	orw	%dx,%ax
	andw	$0xffc0,%dx
	orw	%cx,%dx
	movq	%rdx,(%rsp)
	ldmxcsr	(%rsp)
	andq	$0x3f,%rax
	addq	$32,%rsp
	ret
	.align	16
	SET_SIZE(__swapEX)

/*
 * swap rounding precision
 *
 * Put bits 1-0 of the argument into FPCW bits 9-8, return the
 * previous FPCW bits 9-8.
 */
	ENTRY(__swapRP)
	subq	$8,%rsp
	fstcw	(%rsp)
	movw	(%rsp),%ax
	movw	%ax,%cx
	andw	$0xfcff,%cx
	andq	$0x3,%rdi
	shlw	$8,%di
	orw	%di,%cx
	movq	%rcx,(%rsp)
	fldcw	(%rsp)
	shrw	$8,%ax
	andq	$0x3,%rax
	addq	$8,%rsp
	ret
	.align	16
	SET_SIZE(__swapRP)

/*
 * swap rounding direction
 *
 * Put bits 1-0 of the argument into FPCW bits 11-10 and MXCSR
 * bits 14-13, return the previous FPCW bits 11-10.
 */
	ENTRY(__swapRD)
	subq	$8,%rsp
	fstcw	(%rsp)
	movw	(%rsp),%ax
	movw	%ax,%cx
	andw	$0xf3ff,%cx
	andq	$0x3,%rdi
	shlw	$10,%di
	orw	%di,%cx
	movq	%rcx,(%rsp)
	fldcw	(%rsp)
	stmxcsr	(%rsp)
	movq	(%rsp),%rcx
	andw	$0x9fff,%cx
	shlw	$3,%di
	orw	%di,%cx
	movq	%rcx,(%rsp)
	ldmxcsr	(%rsp)
	shrw	$10,%ax
	andq	$0x3,%rax
	addq	$8,%rsp
	ret
	.align	16
	SET_SIZE(__swapRD)
