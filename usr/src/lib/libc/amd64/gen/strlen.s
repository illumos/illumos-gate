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
 * Copyright (c) 2009, Intel Corporation
 * All rights reserved.
 */

/*
 *	strlen - calculate the length of string
 */

#include "SYS.h"
#include "proc64_id.h"

#define LABEL(s) .strlen/**/s

	/*
	 * This implementation uses SSE instructions to compare up to 16 bytes
	 * at a time looking for the end of string (null char).
	 */
	ENTRY(strlen)			/* (const char *s) */
	mov	%rdi, %rsi		/* keep original %rdi value */
	mov	%rsi, %rcx
	pxor	%xmm0, %xmm0		/* 16 null chars */
	and	$15, %rcx	
	jz	LABEL(align16_loop)	/* string is 16 byte aligned */ 		

	/*
	 * Unaligned case. Round down to 16-byte boundary before comparing
	 * 16 bytes for a null char. The code then compensates for any extra chars
	 * preceding the start of the string. 
	 */
LABEL(unalign16):
	and	$0xfffffffffffffff0, %rsi

	pcmpeqb	(%rsi), %xmm0
	lea	16(%rdi), %rsi		
	pmovmskb %xmm0, %edx

	shr	%cl, %edx		/* Compensate for bytes preceding the string */
	test	%edx, %edx
	jnz	LABEL(exit)
	sub	%rcx, %rsi		/* no null, adjust to next 16-byte boundary */
	pxor	%xmm0, %xmm0		/* clear xmm0, may have been changed... */
	
	.p2align 4
LABEL(align16_loop):			/* 16 byte aligned */
	pcmpeqb	(%rsi), %xmm0		/* look for null bytes */
	pmovmskb %xmm0, %edx		/* move each byte mask of %xmm0 to edx */

	add	$16, %rsi		/* prepare to search next 16 bytes */
	test	%edx, %edx		/* if no null byte, %edx must be 0 */
	jnz	LABEL(exit)		/* found a null */

	pcmpeqb	(%rsi), %xmm0
	pmovmskb %xmm0, %edx
	add	$16, %rsi
	test	%edx, %edx
	jnz	LABEL(exit)

	pcmpeqb	(%rsi), %xmm0
	pmovmskb %xmm0, %edx
	add	$16, %rsi
	test	%edx, %edx
	jnz	LABEL(exit)

	pcmpeqb	(%rsi), %xmm0
	pmovmskb %xmm0, %edx
	add	$16, %rsi
	test	%edx, %edx
	jz	LABEL(align16_loop)

	.p2align 4
LABEL(exit):
	neg	%rdi		
	/*
	 * Check to see if BSF is fast on this processor. If not, use a different
	 * exit tail to find first bit set indicating null byte match.
	 */
	testl	$USE_BSF, .memops_method(%rip)
	jz	LABEL(AMD_exit)

	lea	-16(%rdi, %rsi), %rax	/* calculate exact offset */	
	bsf	%edx, %ecx		/* Least significant 1 bit is index of null */	
	lea	(%rax, %rcx),%rax
	ret

	/*
	 * This exit tail does not use the bsf instruction.
	 */
	.p2align 4
LABEL(AMD_exit):
	lea	-16(%rdi, %rsi), %rax
	test	%dl, %dl	
	jz	LABEL(exit_high)
	test	$0x01, %dl
	jnz	LABEL(exit_tail0)

	test	$0x02, %dl
	jnz	LABEL(exit_tail1)

	.p2align 4		
	test	$0x04, %dl
	jnz	LABEL(exit_tail2)

	test	$0x08, %dl
	jnz	LABEL(exit_tail3)

	test	$0x10, %dl
	jnz	LABEL(exit_tail4)

	test	$0x20, %dl
	jnz	LABEL(exit_tail5)

	test	$0x40, %dl
	jnz	LABEL(exit_tail6)
	add	$7, %rax
	ret

	.p2align 4
LABEL(exit_high):
	add	$8, %rax
	test	$0x01, %dh
	jnz	LABEL(exit_tail0)

	test	$0x02, %dh
	jnz	LABEL(exit_tail1)

	test	$0x04, %dh
	jnz	LABEL(exit_tail2)

	test	$0x08, %dh
	jnz	LABEL(exit_tail3)

	test	$0x10, %dh
	jnz	LABEL(exit_tail4)

	test	$0x20, %dh
	jnz	LABEL(exit_tail5)

	test	$0x40, %dh
	jnz	LABEL(exit_tail6)
	add	$7, %rax
	ret

	.p2align 4
LABEL(exit_tail0):
	xor	%ecx, %ecx
	ret

	.p2align 4
LABEL(exit_tail1):
	add	$1, %rax
	ret

	.p2align 4
LABEL(exit_tail2):
	add	$2, %rax
	ret

	.p2align 4
LABEL(exit_tail3):
	add	$3, %rax
	ret

	.p2align 4
LABEL(exit_tail4):
	add	$4, %rax
	ret

	.p2align 4
LABEL(exit_tail5):
	add	$5, %rax
	ret

	.p2align 4
LABEL(exit_tail6):
	add	$6, %rax
	ret
	SET_SIZE(strlen)
