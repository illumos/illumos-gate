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
 *	str[n]cpy - copy [n] chars from second operand into first operand
 */
#include "SYS.h"
#include "proc64_id.h"

#define LABEL(s) .strcpy/**/s

#ifdef USE_AS_STRNCPY
	ENTRY(strncpy)
	test	%edx, %edx
	jz	LABEL(strncpy_exitz)
	mov	%rdx, %r8
#else
	ENTRY(strcpy)				/* (char *, const char *) */
	xor	%rdx, %rdx
#endif
	mov	%esi, %ecx
	and	$0xfffffffffffffff0, %rsi	/* force rsi 16 byte align */
	and	$0xf, %rcx
	mov	%rdi, %rax			/* save destination address for return value */


	pxor	%xmm0, %xmm0			/* clear %xmm0 for null char checks */
	pcmpeqb	(%rsi), %xmm0			/* check 16 bytes in src for null */
	pmovmskb %xmm0, %edx
	shr	%cl, %edx			/* adjust for offset from 16byte boundary */
	test	%edx, %edx			/* edx will be 0 if chars are non-null */
	jnz	LABEL(less16bytes)		/* null char found in first 16 bytes examined */
#ifdef USE_AS_STRNCPY
	/*
	 * Check if the count is satisfied in first 16 bytes examined.
	 */
	lea	-16(%r8, %rcx), %r11
	cmp	$0, %r11
	jle	LABEL(less16bytes)
#endif
	mov	%rcx, %r9			/* rsi alignment offset */
	or	%edi, %ecx
	and	$0xf, %ecx
	lea	-16(%r9), %r10
	jz	LABEL(ashr_0)			/* src and dest are both 16 byte aligned */

	neg	%r10				/* max src bytes remaining in current dqword */

	pxor	%xmm0, %xmm0			/* clear %xmm0, may be polluted by unaligned operation */
	pcmpeqb	16(%rsi), %xmm0			/* check next 16 bytes in src for a null */
	pmovmskb %xmm0, %edx
	test	%edx, %edx
	jnz	LABEL(less32bytes)		/* null char found in first 32 bytes examined */

#ifdef USE_AS_STRNCPY
	/*
	 * If strncpy count <= 16 go to exit case
	 */
	sub	$16, %r8
	jbe	LABEL(less32bytes_strncpy_truncation)
#endif
	/*
	 * At least 16 bytes to copy to destination string. Move them now.
	 * Don't worry about alignment.
	 */
	mov	(%rsi, %r9), %rdx
	mov	%rdx, (%rdi)
	mov	8(%rsi, %r9), %rdx
	mov	%rdx, 8(%rdi)

	/*
	 * so far destination rdi may be aligned by 16, re-calculate rsi and
	 * jump to corresponding src/dest relative offset case.
	 * 	rcx is offset of rsi
	 * 	rdx is offset of rdi
	 */
	and	$0xfffffffffffffff0, %rdi	/* force rdi 16 byte align */
	mov	%rax, %rdx			/* rax contains orignal rdi */
	xor	%rdi, %rdx			/* same effect as "and $0xf, %rdx" */
#ifdef USE_AS_STRNCPY
	/*
	 * Will now do 16 byte aligned stores. Stores may overlap some bytes
	 * (ie store twice) if destination was unaligned. Compensate here.
	 */
	add	%rdx, %r8			/* compensate for overlap */
#endif

	add	$16, %rdi			/* next 16 bytes for dest */

	/*
	 * align src to 16-byte boundary. Could be up or down depending on
	 * whether src offset - dest offset > 0 (up) or
	 *  src offset - dest offset < 0 (down).
	 */
	sub	%rdx, %r9			/* src offset - dest offset */

	lea	16(%r9, %rsi), %rsi
	mov	%esi, %ecx			/* for new src offset */
	and	$0xfffffffffffffff0, %rsi	/* force rsi 16 byte align */

	and	$0xf, %ecx			/* new src offset is 0 if rsi/rdi have same alignment */
	jz	LABEL(ashr_0)

#ifdef USE_AS_STRNCPY
	xor	%edx, %edx			/* In case unaligned_exit is taken */
#endif
	/*
	 * Jump to case corresponding to source/dest string relative offsets
	 * Index = (16 + (src offset - dest offset)) % 16
	 */
	lea	-16(%rcx), %r10
	mov	%rcx, %r9
	neg	%r10				/* max src bytes remaining in current dqword */
	lea	LABEL(unaligned_table)(%rip), %r11
	movslq	(%r11, %rcx, 4), %rcx
	lea	(%r11, %rcx), %rcx
	jmp	*%rcx

/*
 * ashr_0 handles the following cases:
 * 	src alignment offset = dest alignment offset
 */
	.p2align 5
LABEL(ashr_0):
#ifdef USE_AS_STRNCPY
	sub	$16, %r8
 	jbe	LABEL(strncpy_truncation_aligned)
#endif
	movdqa	(%rsi), %xmm1		/* fetch 16 bytes from src string */
	movdqa	%xmm1, (%rdi)		/* store 16 bytes into dest string */
	add	$16, %rsi
	add	$16, %rdi
	pcmpeqb	(%rsi), %xmm0		/* check 16 bytes in src for a null */
	pmovmskb %xmm0, %edx

	test	%edx, %edx		/* edx will be 0 if chars are non-null */
	jnz	LABEL(aligned_16bytes)	/* exit tail */

LABEL(ashr_0_loop):
#ifdef USE_AS_STRNCPY
	sub	$16, %r8
	jbe	LABEL(strncpy_truncation_aligned)
#endif
	movdqa	(%rsi, %rcx), %xmm1
	movdqa	%xmm1, (%rdi, %rcx)
	add	$16, %rcx
	pcmpeqb	(%rsi, %rcx), %xmm0
	pmovmskb %xmm0, %edx
	test	%edx, %edx
	jnz	LABEL(aligned_exit)

#ifdef USE_AS_STRNCPY
	sub	$16, %r8
	jbe	LABEL(strncpy_truncation_aligned)
#endif
	movdqa  (%rsi, %rcx), %xmm1
	movdqa  %xmm1, (%rdi, %rcx)
	add	$16, %rcx
	pcmpeqb  (%rsi, %rcx), %xmm0
	pmovmskb  %xmm0, %edx
	test	%edx, %edx
	jnz	LABEL(aligned_exit)

#ifdef USE_AS_STRNCPY
	sub	$16, %r8
	jbe	LABEL(strncpy_truncation_aligned)
#endif
	movdqa  (%rsi, %rcx), %xmm1
	movdqa  %xmm1, (%rdi, %rcx)

	add	$16, %rcx
	pcmpeqb  (%rsi, %rcx), %xmm0
	pmovmskb  %xmm0, %edx
	test	%edx, %edx
	jnz	LABEL(aligned_exit)

#ifdef USE_AS_STRNCPY
	sub	$16, %r8
	jbe	LABEL(strncpy_truncation_aligned)
#endif
	movdqa  (%rsi, %rcx), %xmm1
	movdqa  %xmm1, (%rdi, %rcx)
	add	$16, %rcx
	pcmpeqb  (%rsi, %rcx), %xmm0
	pmovmskb  %xmm0, %edx
	test	%edx, %edx
	jz	LABEL(ashr_0_loop)
	jmp	LABEL(aligned_exit)


/*
 * ashr_15 handles the following cases:
 * 	(16 + (src offset - dest offset)) % 16 = 15 
 *
 * Based on above operation, start from (%r9 + rsi) to the left of this cache
 * bank, there is no null byte.
 */
	.p2align 4
LABEL(ashr_15):
	xor	%ecx, %ecx				/* clear index */
#ifdef USE_AS_STRNCPY
	cmp	%r10, %r8
	jbe	LABEL(unaligned_exit)
#endif
	testl	$USE_SSSE3, .memops_method(%rip)	/* use sse2 or ssse3? */
	jz	LABEL(ashr_15_use_sse2)

	.p2align 4
LABEL(ashr_15_use_ssse3):
	movdqa	16(%rsi, %rcx), %xmm3
	pcmpeqb	%xmm3, %xmm0
	pmovmskb %xmm0, %edx
	test	%edx, %edx
	jnz	LABEL(unaligned_exit)
#ifdef USE_AS_STRNCPY
	sub	$16, %r8
 	jbe	LABEL(strncpy_truncation_unaligned)
#endif

	#palignr $15, (%rsi, %rcx), %xmm3
	.byte	0x66, 0x0F, 0x3A ,0x0F
	.byte	0x1c, 0x0e, 0x0f

	movdqa	%xmm3, (%rdi, %rcx)
	add	$16, %rcx

#ifdef USE_AS_STRNCPY
	cmp	%r10, %r8
	jbe	LABEL(unaligned_exit)
#endif
	movdqa	16(%rsi, %rcx), %xmm3
	pcmpeqb %xmm3, %xmm0
	pmovmskb %xmm0, %edx
	test	%edx, %edx
	jnz	LABEL(unaligned_exit)
#ifdef USE_AS_STRNCPY
	sub	$16, %r8
 	jbe	LABEL(strncpy_truncation_unaligned)
#endif

	#palignr $15, (%rsi, %rcx), %xmm3
	.byte	0x66, 0x0F, 0x3A ,0x0F
	.byte	0x1c, 0x0e, 0x0f

	movdqa	%xmm3, (%rdi, %rcx)
	add	$16, %rcx

#ifdef USE_AS_STRNCPY
	cmp	%r10, %r8
	jbe	LABEL(unaligned_exit)
#endif
	jmp	LABEL(ashr_15_use_ssse3)

	.p2align 4
LABEL(ashr_15_use_sse2):
	pcmpeqb 16(%rsi, %rcx), %xmm0
	pmovmskb %xmm0, %edx
	test	%edx, %edx
	jnz	LABEL(unaligned_exit)
#ifdef USE_AS_STRNCPY
	sub	$16, %r8
 	jbe	LABEL(strncpy_truncation_unaligned)
#endif

	movdqa	16(%rsi, %rcx), %xmm3
	movdqa	(%rsi, %rcx), %xmm2

	psrldq	$15, %xmm2
	pslldq	$1, %xmm3
	por	%xmm2, %xmm3

	movdqa	%xmm3, (%rdi, %rcx)
	add	$16, %rcx
#ifdef USE_AS_STRNCPY
	cmp	%r10, %r8
	jbe	LABEL(unaligned_exit)
#endif
	pcmpeqb 16(%rsi, %rcx), %xmm0
	pmovmskb %xmm0, %edx
	test	%edx, %edx
	jnz	LABEL(unaligned_exit)
#ifdef USE_AS_STRNCPY
	sub	$16, %r8
 	jbe	LABEL(strncpy_truncation_unaligned)
#endif

	movdqa	16(%rsi, %rcx), %xmm3
	movdqa	(%rsi, %rcx), %xmm2

	psrldq	$15, %xmm2
	pslldq	$1, %xmm3
	por	%xmm2, %xmm3

	movdqa	%xmm3, (%rdi, %rcx)
	add	$16, %rcx
#ifdef USE_AS_STRNCPY
	cmp	%r10, %r8
	jbe	LABEL(unaligned_exit)
#endif
	jmp	LABEL(ashr_15_use_sse2)


/*
 * ashr_14 handles the following cases:
 * 	(16 + (src offset - dest offset)) % 16 = 14 
 *
 * Based on above operation, start from (%r9 + rsi) to the left of this cache
 * bank, there is no null byte.
 */
	.p2align 4
LABEL(ashr_14):
	xor	%ecx, %ecx				/* clear index */
#ifdef USE_AS_STRNCPY
	cmp	%r10, %r8
	jbe	LABEL(unaligned_exit)
#endif
	testl	$USE_SSSE3, .memops_method(%rip)	/* use sse2 or ssse3? */
	jz	LABEL(ashr_14_use_sse2)

	.p2align 4
LABEL(ashr_14_use_ssse3):
	movdqa	16(%rsi, %rcx), %xmm3
	pcmpeqb	%xmm3, %xmm0
	pmovmskb %xmm0, %edx
	test	%edx, %edx
	jnz	LABEL(unaligned_exit)
#ifdef USE_AS_STRNCPY
	sub	$16, %r8
 	jbe	LABEL(strncpy_truncation_unaligned)
#endif

	#palignr $14, (%rsi, %rcx), %xmm3
	.byte	0x66, 0x0F, 0x3A ,0x0F
	.byte	0x1c, 0x0e, 0x0e

	movdqa	%xmm3, (%rdi, %rcx)
	add	$16, %rcx

#ifdef USE_AS_STRNCPY
	cmp	%r10, %r8
	jbe	LABEL(unaligned_exit)
#endif
	movdqa	16(%rsi, %rcx), %xmm3
	pcmpeqb %xmm3, %xmm0
	pmovmskb %xmm0, %edx
	test	%edx, %edx
	jnz	LABEL(unaligned_exit)
#ifdef USE_AS_STRNCPY
	sub	$16, %r8
 	jbe	LABEL(strncpy_truncation_unaligned)
#endif

	#palignr $14, (%rsi, %rcx), %xmm3
	.byte	0x66, 0x0F, 0x3A ,0x0F
	.byte	0x1c, 0x0e, 0x0e

	movdqa	%xmm3, (%rdi, %rcx)
	add	$16, %rcx
#ifdef USE_AS_STRNCPY
	cmp	%r10, %r8
	jbe	LABEL(unaligned_exit)
#endif
	jmp	LABEL(ashr_14_use_ssse3)

	.p2align 4
LABEL(ashr_14_use_sse2):
	pcmpeqb 16(%rsi, %rcx), %xmm0
	pmovmskb %xmm0, %edx
	test	%edx, %edx
	jnz	LABEL(unaligned_exit)
#ifdef USE_AS_STRNCPY
	sub	$16, %r8
 	jbe	LABEL(strncpy_truncation_unaligned)
#endif

	movdqa	16(%rsi, %rcx), %xmm3
	movdqa	(%rsi, %rcx), %xmm2

	psrldq	$14, %xmm2
	pslldq	$2, %xmm3
	por	%xmm2, %xmm3

	movdqa	%xmm3, (%rdi, %rcx)
	add	$16, %rcx

#ifdef USE_AS_STRNCPY
	cmp	%r10, %r8
	jbe	LABEL(unaligned_exit)
#endif
	pcmpeqb 16(%rsi, %rcx), %xmm0
	pmovmskb %xmm0, %edx
	test	%edx, %edx
	jnz	LABEL(unaligned_exit)
#ifdef USE_AS_STRNCPY
	sub	$16, %r8
 	jbe	LABEL(strncpy_truncation_unaligned)
#endif

	movdqa	16(%rsi, %rcx), %xmm3
	movdqa	(%rsi, %rcx), %xmm2

	psrldq	$14, %xmm2
	pslldq	$2, %xmm3
	por	%xmm2, %xmm3

	movdqa	%xmm3, (%rdi, %rcx)
	add	$16, %rcx
#ifdef USE_AS_STRNCPY
	cmp	%r10, %r8
	jbe	LABEL(unaligned_exit)
#endif
	jmp	LABEL(ashr_14_use_sse2)


/*
 * ashr_13 handles the following cases:
 * 	(16 + (src offset - dest offset)) % 16 = 13 
 *
 * Based on above operation, start from (%r9 + rsi) to the left of this cache
 * bank, there is no null byte.
 */
	.p2align 4
LABEL(ashr_13):
	xor	%ecx, %ecx				/* clear index */
#ifdef USE_AS_STRNCPY
	cmp	%r10, %r8
	jbe	LABEL(unaligned_exit)
#endif
	testl	$USE_SSSE3, .memops_method(%rip)	/* use sse2 or ssse3? */
	jz	LABEL(ashr_13_use_sse2)

	.p2align 4
LABEL(ashr_13_use_ssse3):
	movdqa	16(%rsi, %rcx), %xmm3
	pcmpeqb	%xmm3, %xmm0
	pmovmskb %xmm0, %edx
	test	%edx, %edx
	jnz	LABEL(unaligned_exit)
#ifdef USE_AS_STRNCPY
	sub	$16, %r8
 	jbe	LABEL(strncpy_truncation_unaligned)
#endif

	#palignr $13, (%rsi, %rcx), %xmm3
	.byte	0x66, 0x0F, 0x3A ,0x0F
	.byte	0x1c, 0x0e, 0x0d

	movdqa	%xmm3, (%rdi, %rcx)
	add	$16, %rcx

#ifdef USE_AS_STRNCPY
	cmp	%r10, %r8
	jbe	LABEL(unaligned_exit)
#endif
	movdqa	16(%rsi, %rcx), %xmm3
	pcmpeqb %xmm3, %xmm0
	pmovmskb %xmm0, %edx
	test	%edx, %edx
	jnz	LABEL(unaligned_exit)
#ifdef USE_AS_STRNCPY
	sub	$16, %r8
 	jbe	LABEL(strncpy_truncation_unaligned)
#endif

	#palignr $13, (%rsi, %rcx), %xmm3
	.byte	0x66, 0x0F, 0x3A ,0x0F
	.byte	0x1c, 0x0e, 0x0d

	movdqa	%xmm3, (%rdi, %rcx)
	add	$16, %rcx
#ifdef USE_AS_STRNCPY
	cmp	%r10, %r8
	jbe	LABEL(unaligned_exit)
#endif
	jmp	LABEL(ashr_13_use_ssse3)

	.p2align 4
LABEL(ashr_13_use_sse2):
	pcmpeqb 16(%rsi, %rcx), %xmm0
	pmovmskb %xmm0, %edx
	test	%edx, %edx
	jnz	LABEL(unaligned_exit)
#ifdef USE_AS_STRNCPY
	sub	$16, %r8
 	jbe	LABEL(strncpy_truncation_unaligned)
#endif

	movdqa	16(%rsi, %rcx), %xmm3
	movdqa	(%rsi, %rcx), %xmm2

	psrldq	$13, %xmm2
	pslldq	$3, %xmm3
	por	%xmm2, %xmm3

	movdqa	%xmm3, (%rdi, %rcx)
	add	$16, %rcx

#ifdef USE_AS_STRNCPY
	cmp	%r10, %r8
	jbe	LABEL(unaligned_exit)
#endif
	pcmpeqb 16(%rsi, %rcx), %xmm0
	pmovmskb %xmm0, %edx
	test	%edx, %edx
	jnz	LABEL(unaligned_exit)
#ifdef USE_AS_STRNCPY
	sub	$16, %r8
 	jbe	LABEL(strncpy_truncation_unaligned)
#endif

	movdqa	16(%rsi, %rcx), %xmm3
	movdqa	(%rsi, %rcx), %xmm2

	psrldq	$13, %xmm2
	pslldq	$3, %xmm3
	por	%xmm2, %xmm3

	movdqa	%xmm3, (%rdi, %rcx)
	add	$16, %rcx
#ifdef USE_AS_STRNCPY
	cmp	%r10, %r8
	jbe	LABEL(unaligned_exit)
#endif
	jmp	LABEL(ashr_13_use_sse2)


/*
 * ashr_12 handles the following cases:
 * 	(16 + (src offset - dest offset)) % 16 = 12 
 *
 * Based on above operation, start from (%r9 + rsi) to the left of this cache
 * bank, there is no null byte.
 */
	.p2align 4
LABEL(ashr_12):
	xor	%ecx, %ecx				/* clear index */
#ifdef USE_AS_STRNCPY
	cmp	%r10, %r8
	jbe	LABEL(unaligned_exit)
#endif
	testl	$USE_SSSE3, .memops_method(%rip)	/* use sse2 or ssse3? */
	jz	LABEL(ashr_12_use_sse2)

	.p2align 4
LABEL(ashr_12_use_ssse3):
	movdqa	16(%rsi, %rcx), %xmm3
	pcmpeqb	%xmm3, %xmm0
	pmovmskb %xmm0, %edx
	test	%edx, %edx
	jnz	LABEL(unaligned_exit)
#ifdef USE_AS_STRNCPY
	sub	$16, %r8
 	jbe	LABEL(strncpy_truncation_unaligned)
#endif

	#palignr $12, (%rsi, %rcx), %xmm3
	.byte	0x66, 0x0F, 0x3A ,0x0F
	.byte	0x1c, 0x0e, 0x0c

	movdqa	%xmm3, (%rdi, %rcx)
	add	$16, %rcx

#ifdef USE_AS_STRNCPY
	cmp	%r10, %r8
	jbe	LABEL(unaligned_exit)
#endif
	movdqa	16(%rsi, %rcx), %xmm3
	pcmpeqb %xmm3, %xmm0
	pmovmskb %xmm0, %edx
	test	%edx, %edx
	jnz	LABEL(unaligned_exit)
#ifdef USE_AS_STRNCPY
	sub	$16, %r8
 	jbe	LABEL(strncpy_truncation_unaligned)
#endif

	#palignr $12, (%rsi, %rcx), %xmm3
	.byte	0x66, 0x0F, 0x3A ,0x0F
	.byte	0x1c, 0x0e, 0x0c

	movdqa	%xmm3, (%rdi, %rcx)
	add	$16, %rcx
#ifdef USE_AS_STRNCPY
	cmp	%r10, %r8
	jbe	LABEL(unaligned_exit)
#endif
	jmp	LABEL(ashr_12_use_ssse3)

	.p2align 4
LABEL(ashr_12_use_sse2):
	pcmpeqb 16(%rsi, %rcx), %xmm0
	pmovmskb %xmm0, %edx
	test	%edx, %edx
	jnz	LABEL(unaligned_exit)
#ifdef USE_AS_STRNCPY
	sub	$16, %r8
 	jbe	LABEL(strncpy_truncation_unaligned)
#endif

	movdqa	16(%rsi, %rcx), %xmm3
	movdqa	(%rsi, %rcx), %xmm2

	psrldq	$12, %xmm2
	pslldq	$4, %xmm3
	por	%xmm2, %xmm3

	movdqa	%xmm3, (%rdi, %rcx)
	add	$16, %rcx

#ifdef USE_AS_STRNCPY
	cmp	%r10, %r8
	jbe	LABEL(unaligned_exit)
#endif
	pcmpeqb 16(%rsi, %rcx), %xmm0
	pmovmskb %xmm0, %edx
	test	%edx, %edx
	jnz	LABEL(unaligned_exit)
#ifdef USE_AS_STRNCPY
	sub	$16, %r8
 	jbe	LABEL(strncpy_truncation_unaligned)
#endif

	movdqa	16(%rsi, %rcx), %xmm3
	movdqa	(%rsi, %rcx), %xmm2

	psrldq	$12, %xmm2
	pslldq	$4, %xmm3
	por	%xmm2, %xmm3

	movdqa	%xmm3, (%rdi, %rcx)
	add	$16, %rcx
#ifdef USE_AS_STRNCPY
	cmp	%r10, %r8
	jbe	LABEL(unaligned_exit)
#endif
	jmp	LABEL(ashr_12_use_sse2)


/*
 * ashr_11 handles the following cases:
 * 	(16 + (src offset - dest offset)) % 16 = 11 
 *
 * Based on above operation, start from (%r9 + rsi) to the left of this cache
 * bank, there is no null byte.
 */
	.p2align 4
LABEL(ashr_11):
	xor	%ecx, %ecx				/* clear index */
#ifdef USE_AS_STRNCPY
	cmp	%r10, %r8
	jbe	LABEL(unaligned_exit)
#endif
	testl	$USE_SSSE3, .memops_method(%rip)	/* use sse2 or ssse3? */
	jz	LABEL(ashr_11_use_sse2)

	.p2align 4
LABEL(ashr_11_use_ssse3):
	movdqa	16(%rsi, %rcx), %xmm3
	pcmpeqb	%xmm3, %xmm0
	pmovmskb %xmm0, %edx
	test	%edx, %edx
	jnz	LABEL(unaligned_exit)
#ifdef USE_AS_STRNCPY
	sub	$16, %r8
 	jbe	LABEL(strncpy_truncation_unaligned)
#endif

	#palignr $11, (%rsi, %rcx), %xmm3
	.byte	0x66, 0x0F, 0x3A ,0x0F
	.byte	0x1c, 0x0e, 0x0b

	movdqa	%xmm3, (%rdi, %rcx)
	add	$16, %rcx

#ifdef USE_AS_STRNCPY
	cmp	%r10, %r8
	jbe	LABEL(unaligned_exit)
#endif
	movdqa	16(%rsi, %rcx), %xmm3
	pcmpeqb %xmm3, %xmm0
	pmovmskb %xmm0, %edx
	test	%edx, %edx
	jnz	LABEL(unaligned_exit)
#ifdef USE_AS_STRNCPY
	sub	$16, %r8
 	jbe	LABEL(strncpy_truncation_unaligned)
#endif

	#palignr $11, (%rsi, %rcx), %xmm3
	.byte	0x66, 0x0F, 0x3A ,0x0F
	.byte	0x1c, 0x0e, 0x0b

	movdqa	%xmm3, (%rdi, %rcx)
	add	$16, %rcx
#ifdef USE_AS_STRNCPY
	cmp	%r10, %r8
	jbe	LABEL(unaligned_exit)
#endif
	jmp	LABEL(ashr_11_use_ssse3)

	.p2align 4
LABEL(ashr_11_use_sse2):
	pcmpeqb 16(%rsi, %rcx), %xmm0
	pmovmskb %xmm0, %edx
	test	%edx, %edx
	jnz	LABEL(unaligned_exit)
#ifdef USE_AS_STRNCPY
	sub	$16, %r8
 	jbe	LABEL(strncpy_truncation_unaligned)
#endif

	movdqa	16(%rsi, %rcx), %xmm3
	movdqa	(%rsi, %rcx), %xmm2

	psrldq	$11, %xmm2
	pslldq	$5, %xmm3
	por	%xmm2, %xmm3

	movdqa	%xmm3, (%rdi, %rcx)
	add	$16, %rcx

#ifdef USE_AS_STRNCPY
	cmp	%r10, %r8
	jbe	LABEL(unaligned_exit)
#endif
	pcmpeqb 16(%rsi, %rcx), %xmm0
	pmovmskb %xmm0, %edx
	test	%edx, %edx
	jnz	LABEL(unaligned_exit)
#ifdef USE_AS_STRNCPY
	sub	$16, %r8
 	jbe	LABEL(strncpy_truncation_unaligned)
#endif

	movdqa	16(%rsi, %rcx), %xmm3
	movdqa	(%rsi, %rcx), %xmm2

	psrldq	$11, %xmm2
	pslldq	$5, %xmm3
	por	%xmm2, %xmm3

	movdqa	%xmm3, (%rdi, %rcx)
	add	$16, %rcx
#ifdef USE_AS_STRNCPY
	cmp	%r10, %r8
	jbe	LABEL(unaligned_exit)
#endif
	jmp	LABEL(ashr_11_use_sse2)


/*
 * ashr_10 handles the following cases:
 * 	(16 + (src offset - dest offset)) % 16 = 10
 *
 * Based on above operation, start from (%r9 + rsi) to the left of this cache
 * bank, there is no null byte.
 */
	.p2align 4
LABEL(ashr_10):
	xor	%ecx, %ecx				/* clear index */
#ifdef USE_AS_STRNCPY
	cmp	%r10, %r8
	jbe	LABEL(unaligned_exit)
#endif
	testl	$USE_SSSE3, .memops_method(%rip)	/* use sse2 or ssse3? */
	jz	LABEL(ashr_10_use_sse2)

	.p2align 4
LABEL(ashr_10_use_ssse3):
	movdqa	16(%rsi, %rcx), %xmm3
	pcmpeqb	%xmm3, %xmm0
	pmovmskb %xmm0, %edx
	test	%edx, %edx
	jnz	LABEL(unaligned_exit)
#ifdef USE_AS_STRNCPY
	sub	$16, %r8
 	jbe	LABEL(strncpy_truncation_unaligned)
#endif

	#palignr $10, (%rsi, %rcx), %xmm3
	.byte	0x66, 0x0F, 0x3A ,0x0F
	.byte	0x1c, 0x0e, 0x0a

	movdqa	%xmm3, (%rdi, %rcx)
	add	$16, %rcx

#ifdef USE_AS_STRNCPY
	cmp	%r10, %r8
	jbe	LABEL(unaligned_exit)
#endif
	movdqa	16(%rsi, %rcx), %xmm3
	pcmpeqb %xmm3, %xmm0
	pmovmskb %xmm0, %edx
	test	%edx, %edx
	jnz	LABEL(unaligned_exit)
#ifdef USE_AS_STRNCPY
	sub	$16, %r8
 	jbe	LABEL(strncpy_truncation_unaligned)
#endif

	#palignr $10, (%rsi, %rcx), %xmm3
	.byte	0x66, 0x0F, 0x3A ,0x0F
	.byte	0x1c, 0x0e, 0x0a

	movdqa	%xmm3, (%rdi, %rcx)
	add	$16, %rcx
#ifdef USE_AS_STRNCPY
	cmp	%r10, %r8
	jbe	LABEL(unaligned_exit)
#endif
	jmp	LABEL(ashr_10_use_ssse3)

	.p2align 4
LABEL(ashr_10_use_sse2):
	pcmpeqb 16(%rsi, %rcx), %xmm0
	pmovmskb %xmm0, %edx
	test	%edx, %edx
	jnz	LABEL(unaligned_exit)
#ifdef USE_AS_STRNCPY
	sub	$16, %r8
 	jbe	LABEL(strncpy_truncation_unaligned)
#endif

	movdqa	16(%rsi, %rcx), %xmm3
	movdqa	(%rsi, %rcx), %xmm2

	psrldq	$10, %xmm2
	pslldq	$6, %xmm3
	por	%xmm2, %xmm3

	movdqa	%xmm3, (%rdi, %rcx)
	add	$16, %rcx

#ifdef USE_AS_STRNCPY
	cmp	%r10, %r8
	jbe	LABEL(unaligned_exit)
#endif
	pcmpeqb 16(%rsi, %rcx), %xmm0
	pmovmskb %xmm0, %edx
	test	%edx, %edx
	jnz	LABEL(unaligned_exit)
#ifdef USE_AS_STRNCPY
	sub	$16, %r8
 	jbe	LABEL(strncpy_truncation_unaligned)
#endif

	movdqa	16(%rsi, %rcx), %xmm3
	movdqa	(%rsi, %rcx), %xmm2

	psrldq	$10, %xmm2
	pslldq	$6, %xmm3
	por	%xmm2, %xmm3

	movdqa	%xmm3, (%rdi, %rcx)
	add	$16, %rcx
#ifdef USE_AS_STRNCPY
	cmp	%r10, %r8
	jbe	LABEL(unaligned_exit)
#endif
	jmp	LABEL(ashr_10_use_sse2)


/*
 * ashr_9 handles the following cases:
 * 	(16 + (src offset - dest offset)) % 16 = 9
 *
 * Based on above operation, start from (%r9 + rsi) to the left of this cache
 * bank, there is no null byte.
 */
	.p2align 4
LABEL(ashr_9):
	xor	%ecx, %ecx				/* clear index */
#ifdef USE_AS_STRNCPY
	cmp	%r10, %r8
	jbe	LABEL(unaligned_exit)
#endif
	testl	$USE_SSSE3, .memops_method(%rip)	/* use sse2 or ssse3? */
	jz	LABEL(ashr_9_use_sse2)

	.p2align 4
LABEL(ashr_9_use_ssse3):
	movdqa	16(%rsi, %rcx), %xmm3
	pcmpeqb	%xmm3, %xmm0
	pmovmskb %xmm0, %edx
	test	%edx, %edx
	jnz	LABEL(unaligned_exit)
#ifdef USE_AS_STRNCPY
	sub	$16, %r8
 	jbe	LABEL(strncpy_truncation_unaligned)
#endif

	#palignr $9, (%rsi, %rcx), %xmm3
	.byte	0x66, 0x0F, 0x3A ,0x0F
	.byte	0x1c, 0x0e, 0x09

	movdqa	%xmm3, (%rdi, %rcx)
	add	$16, %rcx

#ifdef USE_AS_STRNCPY
	cmp	%r10, %r8
	jbe	LABEL(unaligned_exit)
#endif
	movdqa	16(%rsi, %rcx), %xmm3
	pcmpeqb %xmm3, %xmm0
	pmovmskb %xmm0, %edx
	test	%edx, %edx
	jnz	LABEL(unaligned_exit)
#ifdef USE_AS_STRNCPY
	sub	$16, %r8
 	jbe	LABEL(strncpy_truncation_unaligned)
#endif

	#palignr $9, (%rsi, %rcx), %xmm3
	.byte	0x66, 0x0F, 0x3A ,0x0F
	.byte	0x1c, 0x0e, 0x09

	movdqa	%xmm3, (%rdi, %rcx)
	add	$16, %rcx
#ifdef USE_AS_STRNCPY
	cmp	%r10, %r8
	jbe	LABEL(unaligned_exit)
#endif
	jmp	LABEL(ashr_9_use_ssse3)

	.p2align 4
LABEL(ashr_9_use_sse2):
	pcmpeqb 16(%rsi, %rcx), %xmm0
	pmovmskb %xmm0, %edx
	test	%edx, %edx
	jnz	LABEL(unaligned_exit)
#ifdef USE_AS_STRNCPY
	sub	$16, %r8
 	jbe	LABEL(strncpy_truncation_unaligned)
#endif

	movdqa	16(%rsi, %rcx), %xmm3
	movdqa	(%rsi, %rcx), %xmm2

	psrldq	$9, %xmm2
	pslldq	$7, %xmm3
	por	%xmm2, %xmm3

	movdqa	%xmm3, (%rdi, %rcx)
	add	$16, %rcx

#ifdef USE_AS_STRNCPY
	cmp	%r10, %r8
	jbe	LABEL(unaligned_exit)
#endif
	pcmpeqb 16(%rsi, %rcx), %xmm0
	pmovmskb %xmm0, %edx
	test	%edx, %edx
	jnz	LABEL(unaligned_exit)
#ifdef USE_AS_STRNCPY
	sub	$16, %r8
 	jbe	LABEL(strncpy_truncation_unaligned)
#endif

	movdqa	16(%rsi, %rcx), %xmm3
	movdqa	(%rsi, %rcx), %xmm2

	psrldq	$9, %xmm2
	pslldq	$7, %xmm3
	por	%xmm2, %xmm3

	movdqa	%xmm3, (%rdi, %rcx)
	add	$16, %rcx
#ifdef USE_AS_STRNCPY
	cmp	%r10, %r8
	jbe	LABEL(unaligned_exit)
#endif
	jmp	LABEL(ashr_9_use_sse2)


/*
 * ashr_8 handles the following cases:
 * 	(16 + (src offset - dest offset)) % 16 = 8
 *
 * Based on above operation, start from (%r9 + rsi) to the left of this cache
 * bank, there is no null byte.
 */
	.p2align 4
LABEL(ashr_8):
	xor	%ecx, %ecx				/* clear index */
#ifdef USE_AS_STRNCPY
	cmp	%r10, %r8
	jbe	LABEL(unaligned_exit)
#endif
	testl	$USE_SSSE3, .memops_method(%rip)	/* use sse2 or ssse3? */
	jz	LABEL(ashr_8_use_sse2)

	.p2align 4
LABEL(ashr_8_use_ssse3):
	movdqa	16(%rsi, %rcx), %xmm3
	pcmpeqb	%xmm3, %xmm0
	pmovmskb %xmm0, %edx
	test	%edx, %edx
	jnz	LABEL(unaligned_exit)
#ifdef USE_AS_STRNCPY
	sub	$16, %r8
 	jbe	LABEL(strncpy_truncation_unaligned)
#endif

	#palignr $8, (%rsi, %rcx), %xmm3
	.byte	0x66, 0x0F, 0x3A ,0x0F
	.byte	0x1c, 0x0e, 0x08

	movdqa	%xmm3, (%rdi, %rcx)
	add	$16, %rcx

#ifdef USE_AS_STRNCPY
	cmp	%r10, %r8
	jbe	LABEL(unaligned_exit)
#endif
	movdqa	16(%rsi, %rcx), %xmm3
	pcmpeqb %xmm3, %xmm0
	pmovmskb %xmm0, %edx
	test	%edx, %edx
	jnz	LABEL(unaligned_exit)
#ifdef USE_AS_STRNCPY
	sub	$16, %r8
 	jbe	LABEL(strncpy_truncation_unaligned)
#endif

	#palignr $8, (%rsi, %rcx), %xmm3
	.byte	0x66, 0x0F, 0x3A ,0x0F
	.byte	0x1c, 0x0e, 0x08

	movdqa	%xmm3, (%rdi, %rcx)
	add	$16, %rcx
#ifdef USE_AS_STRNCPY
	cmp	%r10, %r8
	jbe	LABEL(unaligned_exit)
#endif
	jmp	LABEL(ashr_8_use_ssse3)

	.p2align 4
LABEL(ashr_8_use_sse2):
	pcmpeqb 16(%rsi, %rcx), %xmm0
	pmovmskb %xmm0, %edx
	test	%edx, %edx
	jnz	LABEL(unaligned_exit)
#ifdef USE_AS_STRNCPY
	sub	$16, %r8
 	jbe	LABEL(strncpy_truncation_unaligned)
#endif

	movdqa	16(%rsi, %rcx), %xmm3
	movdqa	(%rsi, %rcx), %xmm2

	psrldq	$8, %xmm2
	pslldq	$8, %xmm3
	por	%xmm2, %xmm3

	movdqa	%xmm3, (%rdi, %rcx)
	add	$16, %rcx

#ifdef USE_AS_STRNCPY
	cmp	%r10, %r8
	jbe	LABEL(unaligned_exit)
#endif
	pcmpeqb 16(%rsi, %rcx), %xmm0
	pmovmskb %xmm0, %edx
	test	%edx, %edx
	jnz	LABEL(unaligned_exit)
#ifdef USE_AS_STRNCPY
	sub	$16, %r8
 	jbe	LABEL(strncpy_truncation_unaligned)
#endif

	movdqa	16(%rsi, %rcx), %xmm3
	movdqa	(%rsi, %rcx), %xmm2

	psrldq	$8, %xmm2
	pslldq	$8, %xmm3
	por	%xmm2, %xmm3

	movdqa	%xmm3, (%rdi, %rcx)
	add	$16, %rcx
#ifdef USE_AS_STRNCPY
	cmp	%r10, %r8
	jbe	LABEL(unaligned_exit)
#endif
	jmp	LABEL(ashr_8_use_sse2)


/*
 * ashr_7 handles the following cases:
 * 	(16 + (src offset - dest offset)) % 16 = 7
 *
 * Based on above operation, start from (%r9 + rsi) to the left of this cache
 * bank, there is no null byte.
 */
	.p2align 4
LABEL(ashr_7):
	xor	%ecx, %ecx				/* clear index */
#ifdef USE_AS_STRNCPY
	cmp	%r10, %r8
	jbe	LABEL(unaligned_exit)
#endif
	testl	$USE_SSSE3, .memops_method(%rip)	/* use sse2 or ssse3? */
	jz	LABEL(ashr_7_use_sse2)

	.p2align 4
LABEL(ashr_7_use_ssse3):
	movdqa	16(%rsi, %rcx), %xmm3
	pcmpeqb	%xmm3, %xmm0
	pmovmskb %xmm0, %edx
	test	%edx, %edx
	jnz	LABEL(unaligned_exit)
#ifdef USE_AS_STRNCPY
	sub	$16, %r8
 	jbe	LABEL(strncpy_truncation_unaligned)
#endif

	#palignr $7, (%rsi, %rcx), %xmm3
	.byte	0x66, 0x0F, 0x3A ,0x0F
	.byte	0x1c, 0x0e, 0x07

	movdqa	%xmm3, (%rdi, %rcx)
	add	$16, %rcx

#ifdef USE_AS_STRNCPY
	cmp	%r10, %r8
	jbe	LABEL(unaligned_exit)
#endif
	movdqa	16(%rsi, %rcx), %xmm3
	pcmpeqb %xmm3, %xmm0
	pmovmskb %xmm0, %edx
	test	%edx, %edx
	jnz	LABEL(unaligned_exit)
#ifdef USE_AS_STRNCPY
	sub	$16, %r8
 	jbe	LABEL(strncpy_truncation_unaligned)
#endif

	#palignr $7, (%rsi, %rcx), %xmm3
	.byte	0x66, 0x0F, 0x3A ,0x0F
	.byte	0x1c, 0x0e, 0x07

	movdqa	%xmm3, (%rdi, %rcx)
	add	$16, %rcx
#ifdef USE_AS_STRNCPY
	cmp	%r10, %r8
	jbe	LABEL(unaligned_exit)
#endif
	jmp	LABEL(ashr_7_use_ssse3)

	.p2align 4
LABEL(ashr_7_use_sse2):
	pcmpeqb 16(%rsi, %rcx), %xmm0
	pmovmskb %xmm0, %edx
	test	%edx, %edx
	jnz	LABEL(unaligned_exit)
#ifdef USE_AS_STRNCPY
	sub	$16, %r8
 	jbe	LABEL(strncpy_truncation_unaligned)
#endif

	movdqa	16(%rsi, %rcx), %xmm3
	movdqa	(%rsi, %rcx), %xmm2

	psrldq	$7, %xmm2
	pslldq	$9, %xmm3
	por	%xmm2, %xmm3

	movdqa	%xmm3, (%rdi, %rcx)
	add	$16, %rcx

#ifdef USE_AS_STRNCPY
	cmp	%r10, %r8
	jbe	LABEL(unaligned_exit)
#endif
	pcmpeqb 16(%rsi, %rcx), %xmm0
	pmovmskb %xmm0, %edx
	test	%edx, %edx
	jnz	LABEL(unaligned_exit)
#ifdef USE_AS_STRNCPY
	sub	$16, %r8
 	jbe	LABEL(strncpy_truncation_unaligned)
#endif

	movdqa	16(%rsi, %rcx), %xmm3
	movdqa	(%rsi, %rcx), %xmm2

	psrldq	$7, %xmm2
	pslldq	$9, %xmm3
	por	%xmm2, %xmm3

	movdqa	%xmm3, (%rdi, %rcx)
	add	$16, %rcx
#ifdef USE_AS_STRNCPY
	cmp	%r10, %r8
	jbe	LABEL(unaligned_exit)
#endif
	jmp	LABEL(ashr_7_use_sse2)


/*
 * ashr_6 handles the following cases:
 * 	(16 + (src offset - dest offset)) % 16 = 6
 *
 * Based on above operation, start from (%r9 + rsi) to the left of this cache
 * bank, there is no null byte.
 */
	.p2align 4
LABEL(ashr_6):
	xor	%ecx, %ecx				/* clear index */
#ifdef USE_AS_STRNCPY
	cmp	%r10, %r8
	jbe	LABEL(unaligned_exit)
#endif
	testl	$USE_SSSE3, .memops_method(%rip)	/* use sse2 or ssse3? */
	jz	LABEL(ashr_6_use_sse2)

	.p2align 4
LABEL(ashr_6_use_ssse3):
	movdqa	16(%rsi, %rcx), %xmm3
	pcmpeqb	%xmm3, %xmm0
	pmovmskb %xmm0, %edx
	test	%edx, %edx
	jnz	LABEL(unaligned_exit)
#ifdef USE_AS_STRNCPY
	sub	$16, %r8
 	jbe	LABEL(strncpy_truncation_unaligned)
#endif

	#palignr $6, (%rsi, %rcx), %xmm3
	.byte	0x66, 0x0F, 0x3A ,0x0F
	.byte	0x1c, 0x0e, 0x06

	movdqa	%xmm3, (%rdi, %rcx)
	add	$16, %rcx

#ifdef USE_AS_STRNCPY
	cmp	%r10, %r8
	jbe	LABEL(unaligned_exit)
#endif
	movdqa	16(%rsi, %rcx), %xmm3
	pcmpeqb %xmm3, %xmm0
	pmovmskb %xmm0, %edx
	test	%edx, %edx
	jnz	LABEL(unaligned_exit)
#ifdef USE_AS_STRNCPY
	sub	$16, %r8
 	jbe	LABEL(strncpy_truncation_unaligned)
#endif

	#palignr $6, (%rsi, %rcx), %xmm3
	.byte	0x66, 0x0F, 0x3A ,0x0F
	.byte	0x1c, 0x0e, 0x06

	movdqa	%xmm3, (%rdi, %rcx)
	add	$16, %rcx
#ifdef USE_AS_STRNCPY
	cmp	%r10, %r8
	jbe	LABEL(unaligned_exit)
#endif
	jmp	LABEL(ashr_6_use_ssse3)

	.p2align 4
LABEL(ashr_6_use_sse2):
	pcmpeqb 16(%rsi, %rcx), %xmm0
	pmovmskb %xmm0, %edx
	test	%edx, %edx
	jnz	LABEL(unaligned_exit)
#ifdef USE_AS_STRNCPY
	sub	$16, %r8
 	jbe	LABEL(strncpy_truncation_unaligned)
#endif

	movdqa	16(%rsi, %rcx), %xmm3
	movdqa	(%rsi, %rcx), %xmm2

	psrldq	$6, %xmm2
	pslldq	$10, %xmm3
	por	%xmm2, %xmm3

	movdqa	%xmm3, (%rdi, %rcx)
	add	$16, %rcx

#ifdef USE_AS_STRNCPY
	cmp	%r10, %r8
	jbe	LABEL(unaligned_exit)
#endif
	pcmpeqb 16(%rsi, %rcx), %xmm0
	pmovmskb %xmm0, %edx
	test	%edx, %edx
	jnz	LABEL(unaligned_exit)
#ifdef USE_AS_STRNCPY
	sub	$16, %r8
 	jbe	LABEL(strncpy_truncation_unaligned)
#endif

	movdqa	16(%rsi, %rcx), %xmm3
	movdqa	(%rsi, %rcx), %xmm2

	psrldq	$6, %xmm2
	pslldq	$10, %xmm3
	por	%xmm2, %xmm3

	movdqa	%xmm3, (%rdi, %rcx)
	add	$16, %rcx
#ifdef USE_AS_STRNCPY
	cmp	%r10, %r8
	jbe	LABEL(unaligned_exit)
#endif
	jmp	LABEL(ashr_6_use_sse2)


/*
 * ashr_5 handles the following cases:
 * 	(16 + (src offset - dest offset)) % 16 = 5
 *
 * Based on above operation, start from (%r9 + rsi) to the left of this cache
 * bank, there is no null byte.
 */
	.p2align 4
LABEL(ashr_5):
	xor	%ecx, %ecx				/* clear index */
#ifdef USE_AS_STRNCPY
	cmp	%r10, %r8
	jbe	LABEL(unaligned_exit)
#endif
	testl	$USE_SSSE3, .memops_method(%rip)	/* use sse2 or ssse3? */
	jz	LABEL(ashr_5_use_sse2)

	.p2align 4
LABEL(ashr_5_use_ssse3):
	movdqa	16(%rsi, %rcx), %xmm3
	pcmpeqb	%xmm3, %xmm0
	pmovmskb %xmm0, %edx
	test	%edx, %edx
	jnz	LABEL(unaligned_exit)
#ifdef USE_AS_STRNCPY
	sub	$16, %r8
 	jbe	LABEL(strncpy_truncation_unaligned)
#endif

	#palignr $5, (%rsi, %rcx), %xmm3
	.byte	0x66, 0x0F, 0x3A ,0x0F
	.byte	0x1c, 0x0e, 0x05

	movdqa	%xmm3, (%rdi, %rcx)
	add	$16, %rcx

#ifdef USE_AS_STRNCPY
	cmp	%r10, %r8
	jbe	LABEL(unaligned_exit)
#endif
	movdqa	16(%rsi, %rcx), %xmm3
	pcmpeqb %xmm3, %xmm0
	pmovmskb %xmm0, %edx
	test	%edx, %edx
	jnz	LABEL(unaligned_exit)
#ifdef USE_AS_STRNCPY
	sub	$16, %r8
 	jbe	LABEL(strncpy_truncation_unaligned)
#endif

	#palignr $5, (%rsi, %rcx), %xmm3
	.byte	0x66, 0x0F, 0x3A ,0x0F
	.byte	0x1c, 0x0e, 0x05

	movdqa	%xmm3, (%rdi, %rcx)
	add	$16, %rcx
#ifdef USE_AS_STRNCPY
	cmp	%r10, %r8
	jbe	LABEL(unaligned_exit)
#endif
	jmp	LABEL(ashr_5_use_ssse3)

	.p2align 4
LABEL(ashr_5_use_sse2):
	pcmpeqb 16(%rsi, %rcx), %xmm0
	pmovmskb %xmm0, %edx
	test	%edx, %edx
	jnz	LABEL(unaligned_exit)
#ifdef USE_AS_STRNCPY
	sub	$16, %r8
 	jbe	LABEL(strncpy_truncation_unaligned)
#endif

	movdqa	16(%rsi, %rcx), %xmm3
	movdqa	(%rsi, %rcx), %xmm2

	psrldq	$5, %xmm2
	pslldq	$11, %xmm3
	por	%xmm2, %xmm3

	movdqa	%xmm3, (%rdi, %rcx)
	add	$16, %rcx

#ifdef USE_AS_STRNCPY
	cmp	%r10, %r8
	jbe	LABEL(unaligned_exit)
#endif
	pcmpeqb 16(%rsi, %rcx), %xmm0
	pmovmskb %xmm0, %edx
	test	%edx, %edx
	jnz	LABEL(unaligned_exit)
#ifdef USE_AS_STRNCPY
	sub	$16, %r8
 	jbe	LABEL(strncpy_truncation_unaligned)
#endif

	movdqa	16(%rsi, %rcx), %xmm3
	movdqa	(%rsi, %rcx), %xmm2

	psrldq	$5, %xmm2
	pslldq	$11, %xmm3
	por	%xmm2, %xmm3

	movdqa	%xmm3, (%rdi, %rcx)
	add	$16, %rcx
#ifdef USE_AS_STRNCPY
	cmp	%r10, %r8
	jbe	LABEL(unaligned_exit)
#endif
	jmp	LABEL(ashr_5_use_sse2)


/*
 * ashr_4 handles the following cases:
 * 	(16 + (src offset - dest offset)) % 16 = 4
 *
 * Based on above operation, start from (%r9 + rsi) to the left of this cache
 * bank, there is no null byte.
 */
	.p2align 4
LABEL(ashr_4):
	xor	%ecx, %ecx				/* clear index */
#ifdef USE_AS_STRNCPY
	cmp	%r10, %r8
	jbe	LABEL(unaligned_exit)
#endif
	testl	$USE_SSSE3, .memops_method(%rip)	/* use sse2 or ssse3? */
	jz	LABEL(ashr_4_use_sse2)

	.p2align 4
LABEL(ashr_4_use_ssse3):
	movdqa	16(%rsi, %rcx), %xmm3
	pcmpeqb	%xmm3, %xmm0
	pmovmskb %xmm0, %edx
	test	%edx, %edx
	jnz	LABEL(unaligned_exit)
#ifdef USE_AS_STRNCPY
	sub	$16, %r8
 	jbe	LABEL(strncpy_truncation_unaligned)
#endif

	#palignr $4, (%rsi, %rcx), %xmm3
	.byte	0x66, 0x0F, 0x3A ,0x0F
	.byte	0x1c, 0x0e, 0x04

	movdqa	%xmm3, (%rdi, %rcx)
	add	$16, %rcx

#ifdef USE_AS_STRNCPY
	cmp	%r10, %r8
	jbe	LABEL(unaligned_exit)
#endif
	movdqa	16(%rsi, %rcx), %xmm3
	pcmpeqb %xmm3, %xmm0
	pmovmskb %xmm0, %edx
	test	%edx, %edx
	jnz	LABEL(unaligned_exit)
#ifdef USE_AS_STRNCPY
	sub	$16, %r8
 	jbe	LABEL(strncpy_truncation_unaligned)
#endif

	#palignr $4, (%rsi, %rcx), %xmm3
	.byte	0x66, 0x0F, 0x3A ,0x0F
	.byte	0x1c, 0x0e, 0x04

	movdqa	%xmm3, (%rdi, %rcx)
	add	$16, %rcx
#ifdef USE_AS_STRNCPY
	cmp	%r10, %r8
	jbe	LABEL(unaligned_exit)
#endif
	jmp	LABEL(ashr_4_use_ssse3)

	.p2align 4
LABEL(ashr_4_use_sse2):
	pcmpeqb 16(%rsi, %rcx), %xmm0
	pmovmskb %xmm0, %edx
	test	%edx, %edx
	jnz	LABEL(unaligned_exit)
#ifdef USE_AS_STRNCPY
	sub	$16, %r8
 	jbe	LABEL(strncpy_truncation_unaligned)
#endif

	movdqa	16(%rsi, %rcx), %xmm3
	movdqa	(%rsi, %rcx), %xmm2

	psrldq	$4, %xmm2
	pslldq	$12, %xmm3
	por	%xmm2, %xmm3

	movdqa	%xmm3, (%rdi, %rcx)
	add	$16, %rcx

#ifdef USE_AS_STRNCPY
	cmp	%r10, %r8
	jbe	LABEL(unaligned_exit)
#endif
	pcmpeqb 16(%rsi, %rcx), %xmm0
	pmovmskb %xmm0, %edx
	test	%edx, %edx
	jnz	LABEL(unaligned_exit)
#ifdef USE_AS_STRNCPY
	sub	$16, %r8
 	jbe	LABEL(strncpy_truncation_unaligned)
#endif

	movdqa	16(%rsi, %rcx), %xmm3
	movdqa	(%rsi, %rcx), %xmm2

	psrldq	$4, %xmm2
	pslldq	$12, %xmm3
	por	%xmm2, %xmm3

	movdqa	%xmm3, (%rdi, %rcx)
	add	$16, %rcx
#ifdef USE_AS_STRNCPY
	cmp	%r10, %r8
	jbe	LABEL(unaligned_exit)
#endif
	jmp	LABEL(ashr_4_use_sse2)


/*
 * ashr_3 handles the following cases:
 * 	(16 + (src offset - dest offset)) % 16 = 3
 *
 * Based on above operation, start from (%r9 + rsi) to the left of this cache
 * bank, there is no null byte.
 */
	.p2align 4
LABEL(ashr_3):
	xor	%ecx, %ecx				/* clear index */
#ifdef USE_AS_STRNCPY
	cmp	%r10, %r8
	jbe	LABEL(unaligned_exit)
#endif
	testl	$USE_SSSE3, .memops_method(%rip)	/* use sse2 or ssse3? */
	jz	LABEL(ashr_3_use_sse2)

	.p2align 4
LABEL(ashr_3_use_ssse3):
	movdqa	16(%rsi, %rcx), %xmm3
	pcmpeqb	%xmm3, %xmm0
	pmovmskb %xmm0, %edx
	test	%edx, %edx
	jnz	LABEL(unaligned_exit)
#ifdef USE_AS_STRNCPY
	sub	$16, %r8
 	jbe	LABEL(strncpy_truncation_unaligned)
#endif

	#palignr $3, (%rsi, %rcx), %xmm3
	.byte	0x66, 0x0F, 0x3A ,0x0F
	.byte	0x1c, 0x0e, 0x03

	movdqa	%xmm3, (%rdi, %rcx)
	add	$16, %rcx

#ifdef USE_AS_STRNCPY
	cmp	%r10, %r8
	jbe	LABEL(unaligned_exit)
#endif
	movdqa	16(%rsi, %rcx), %xmm3
	pcmpeqb %xmm3, %xmm0
	pmovmskb %xmm0, %edx
	test	%edx, %edx
	jnz	LABEL(unaligned_exit)
#ifdef USE_AS_STRNCPY
	sub	$16, %r8
 	jbe	LABEL(strncpy_truncation_unaligned)
#endif

	#palignr $3, (%rsi, %rcx), %xmm3
	.byte	0x66, 0x0F, 0x3A ,0x0F
	.byte	0x1c, 0x0e, 0x03

	movdqa	%xmm3, (%rdi, %rcx)
	add	$16, %rcx
#ifdef USE_AS_STRNCPY
	cmp	%r10, %r8
	jbe	LABEL(unaligned_exit)
#endif
	jmp	LABEL(ashr_3_use_ssse3)

	.p2align 4
LABEL(ashr_3_use_sse2):
	pcmpeqb 16(%rsi, %rcx), %xmm0
	pmovmskb %xmm0, %edx
	test	%edx, %edx
	jnz	LABEL(unaligned_exit)
#ifdef USE_AS_STRNCPY
	sub	$16, %r8
 	jbe	LABEL(strncpy_truncation_unaligned)
#endif

	movdqa	16(%rsi, %rcx), %xmm3
	movdqa	(%rsi, %rcx), %xmm2

	psrldq	$3, %xmm2
	pslldq	$13, %xmm3
	por	%xmm2, %xmm3

	movdqa	%xmm3, (%rdi, %rcx)
	add	$16, %rcx

#ifdef USE_AS_STRNCPY
	cmp	%r10, %r8
	jbe	LABEL(unaligned_exit)
#endif
	pcmpeqb 16(%rsi, %rcx), %xmm0
	pmovmskb %xmm0, %edx
	test	%edx, %edx
	jnz	LABEL(unaligned_exit)
#ifdef USE_AS_STRNCPY
	sub	$16, %r8
 	jbe	LABEL(strncpy_truncation_unaligned)
#endif

	movdqa	16(%rsi, %rcx), %xmm3
	movdqa	(%rsi, %rcx), %xmm2

	psrldq	$3, %xmm2
	pslldq	$13, %xmm3
	por	%xmm2, %xmm3

	movdqa	%xmm3, (%rdi, %rcx)
	add	$16, %rcx
#ifdef USE_AS_STRNCPY
	cmp	%r10, %r8
	jbe	LABEL(unaligned_exit)
#endif
	jmp	LABEL(ashr_3_use_sse2)


/*
 * ashr_2 handles the following cases:
 * 	(16 + (src offset - dest offset)) % 16 = 2
 *
 * Based on above operation, start from (%r9 + rsi) to the left of this cache
 * bank, there is no null byte.
 */
	.p2align 4
LABEL(ashr_2):
	xor	%ecx, %ecx				/* clear index */
#ifdef USE_AS_STRNCPY
	cmp	%r10, %r8
	jbe	LABEL(unaligned_exit)
#endif
	testl	$USE_SSSE3, .memops_method(%rip)	/* use sse2 or ssse3? */
	jz	LABEL(ashr_2_use_sse2)

	.p2align 4
LABEL(ashr_2_use_ssse3):
	movdqa	16(%rsi, %rcx), %xmm3
	pcmpeqb	%xmm3, %xmm0
	pmovmskb %xmm0, %edx
	test	%edx, %edx
	jnz	LABEL(unaligned_exit)
#ifdef USE_AS_STRNCPY
	sub	$16, %r8
 	jbe	LABEL(strncpy_truncation_unaligned)
#endif

	#palignr $2, (%rsi, %rcx), %xmm3
	.byte	0x66, 0x0F, 0x3A ,0x0F
	.byte	0x1c, 0x0e, 0x02

	movdqa	%xmm3, (%rdi, %rcx)
	add	$16, %rcx

#ifdef USE_AS_STRNCPY
	cmp	%r10, %r8
	jbe	LABEL(unaligned_exit)
#endif
	movdqa	16(%rsi, %rcx), %xmm3
	pcmpeqb %xmm3, %xmm0
	pmovmskb %xmm0, %edx
	test	%edx, %edx
	jnz	LABEL(unaligned_exit)
#ifdef USE_AS_STRNCPY
	sub	$16, %r8
 	jbe	LABEL(strncpy_truncation_unaligned)
#endif

	#palignr $2, (%rsi, %rcx), %xmm3
	.byte	0x66, 0x0F, 0x3A ,0x0F
	.byte	0x1c, 0x0e, 0x02

	movdqa	%xmm3, (%rdi, %rcx)
	add	$16, %rcx
#ifdef USE_AS_STRNCPY
	cmp	%r10, %r8
	jbe	LABEL(unaligned_exit)
#endif
	jmp	LABEL(ashr_2_use_ssse3)

	.p2align 4
LABEL(ashr_2_use_sse2):
	pcmpeqb 16(%rsi, %rcx), %xmm0
	pmovmskb %xmm0, %edx
	test	%edx, %edx
	jnz	LABEL(unaligned_exit)
#ifdef USE_AS_STRNCPY
	sub	$16, %r8
 	jbe	LABEL(strncpy_truncation_unaligned)
#endif

	movdqa	16(%rsi, %rcx), %xmm3
	movdqa	(%rsi, %rcx), %xmm2

	psrldq	$2, %xmm2
	pslldq	$14, %xmm3
	por	%xmm2, %xmm3

	movdqa	%xmm3, (%rdi, %rcx)
	add	$16, %rcx

#ifdef USE_AS_STRNCPY
	cmp	%r10, %r8
	jbe	LABEL(unaligned_exit)
#endif
	pcmpeqb 16(%rsi, %rcx), %xmm0
	pmovmskb %xmm0, %edx
	test	%edx, %edx
	jnz	LABEL(unaligned_exit)
#ifdef USE_AS_STRNCPY
	sub	$16, %r8
 	jbe	LABEL(strncpy_truncation_unaligned)
#endif

	movdqa	16(%rsi, %rcx), %xmm3
	movdqa	(%rsi, %rcx), %xmm2

	psrldq	$2, %xmm2
	pslldq	$14, %xmm3
	por	%xmm2, %xmm3

	movdqa	%xmm3, (%rdi, %rcx)
	add	$16, %rcx
#ifdef USE_AS_STRNCPY
	cmp	%r10, %r8
	jbe	LABEL(unaligned_exit)
#endif
	jmp	LABEL(ashr_2_use_sse2)


/*
 * ashr_1 handles the following cases:
 * 	(16 + (src offset - dest offset)) % 16 = 1
 *
 * Based on above operation, start from (%r9 + rsi) to the left of this cache
 * bank, there is no null byte.
 */
	.p2align 4
LABEL(ashr_1):
	xor	%ecx, %ecx				/* clear index */
#ifdef USE_AS_STRNCPY
	cmp	%r10, %r8
	jbe	LABEL(unaligned_exit)
#endif
	testl	$USE_SSSE3, .memops_method(%rip)	/* use sse2 or ssse3? */
	jz	LABEL(ashr_1_use_sse2)

	.p2align 4
LABEL(ashr_1_use_ssse3):
	movdqa	16(%rsi, %rcx), %xmm3
	pcmpeqb	%xmm3, %xmm0
	pmovmskb %xmm0, %edx
	test	%edx, %edx
	jnz	LABEL(unaligned_exit)
#ifdef USE_AS_STRNCPY
	sub	$16, %r8
 	jbe	LABEL(strncpy_truncation_unaligned)
#endif

	#palignr $1, (%rsi, %rcx), %xmm3
	.byte	0x66, 0x0F, 0x3A ,0x0F
	.byte	0x1c, 0x0e, 0x01

	movdqa	%xmm3, (%rdi, %rcx)
	add	$16, %rcx

#ifdef USE_AS_STRNCPY
	cmp	%r10, %r8
	jbe	LABEL(unaligned_exit)
#endif
	movdqa	16(%rsi, %rcx), %xmm3
	pcmpeqb %xmm3, %xmm0
	pmovmskb %xmm0, %edx
	test	%edx, %edx
	jnz	LABEL(unaligned_exit)
#ifdef USE_AS_STRNCPY
	sub	$16, %r8
 	jbe	LABEL(strncpy_truncation_unaligned)
#endif
	#palignr $1, (%rsi, %rcx), %xmm3
	.byte	0x66, 0x0F, 0x3A ,0x0F
	.byte	0x1c, 0x0e, 0x01

	movdqa	%xmm3, (%rdi, %rcx)
	add	$16, %rcx
#ifdef USE_AS_STRNCPY
	cmp	%r10, %r8
	jbe	LABEL(unaligned_exit)
#endif
	jmp	LABEL(ashr_1_use_ssse3)

	.p2align 4
LABEL(ashr_1_use_sse2):
	pcmpeqb 16(%rsi, %rcx), %xmm0
	pmovmskb %xmm0, %edx
	test	%edx, %edx
	jnz	LABEL(unaligned_exit)
#ifdef USE_AS_STRNCPY
	sub	$16, %r8
 	jbe	LABEL(strncpy_truncation_unaligned)
#endif
	movdqa	16(%rsi, %rcx), %xmm3
	movdqa	(%rsi, %rcx), %xmm2

	psrldq	$1, %xmm2
	pslldq	$15, %xmm3
	por	%xmm2, %xmm3

	movdqa	%xmm3, (%rdi, %rcx)
	add	$16, %rcx

#ifdef USE_AS_STRNCPY
	cmp	%r10, %r8
	jbe	LABEL(unaligned_exit)
#endif
	pcmpeqb 16(%rsi, %rcx), %xmm0
	pmovmskb %xmm0, %edx
	test	%edx, %edx
	jnz	LABEL(unaligned_exit)
#ifdef USE_AS_STRNCPY
	sub	$16, %r8
 	jbe	LABEL(strncpy_truncation_unaligned)
#endif

	movdqa	16(%rsi, %rcx), %xmm3
	movdqa	(%rsi, %rcx), %xmm2

	psrldq	$1, %xmm2
	pslldq	$15, %xmm3
	por	%xmm2, %xmm3

	movdqa	%xmm3, (%rdi, %rcx)
	add	$16, %rcx
#ifdef USE_AS_STRNCPY
	cmp	%r10, %r8
	jbe	LABEL(unaligned_exit)
#endif
	jmp	LABEL(ashr_1_use_sse2)


	/*
	 * Exit tail code:
	 * Up to 32 bytes are copied in the case of strcpy.
	 */
	.p2align 4
LABEL(less32bytes):
	xor	%ecx, %ecx
LABEL(unaligned_exit):
	add	%r9, %rsi		/* r9 holds offset of rsi */
	mov	%rcx, %r9
	mov	%r10, %rcx
	shl	%cl, %edx		/* after shl, calculate the exact number to be filled */
	mov	%r9, %rcx
	.p2align 4
LABEL(aligned_exit):
	add	%rcx, %rdi		/* locate exact address for rdi */
LABEL(less16bytes):
	add	%rcx, %rsi		/* locate exact address for rsi */
LABEL(aligned_16bytes):
#ifdef USE_AS_STRNCPY
	/*
	 * Null found in 16bytes checked. Set bit in bitmask corresponding to
	 * the strncpy count argument. We will copy to the null (inclusive)
	 * or count whichever comes first.
	 */
	mov	$1, %r9d
	lea	-1(%r8), %rcx
	shl	%cl, %r9d
	cmp	$32, %r8
	ja	LABEL(strncpy_tail)
	or	%r9d, %edx
LABEL(strncpy_tail):
#endif
	/*
	 * Check to see if BSF is fast on this processor. If not, use a
	 * different exit tail.
	 */
	testb	$USE_BSF, .memops_method(%rip)
	jz	LABEL(AMD_exit)
	bsf	%rdx, %rcx		/* Find byte with null char */
	lea	LABEL(tail_table)(%rip), %r11
	movslq	(%r11, %rcx, 4), %rcx
	lea	(%r11, %rcx), %rcx
	jmp	*%rcx

#ifdef USE_AS_STRNCPY
	/*
	 * Count reached before null found.
	 */
	.p2align 4
LABEL(less32bytes_strncpy_truncation):
	xor	%ecx, %ecx
LABEL(strncpy_truncation_unaligned):
	add	%r9, %rsi		/* next src char to copy */
LABEL(strncpy_truncation_aligned):
	add	%rcx, %rdi
	add	%rcx, %rsi
	add	$16, %r8		/* compensation */
	lea	-1(%r8), %rcx
	lea	LABEL(tail_table)(%rip), %r11
	movslq	(%r11, %rcx, 4), %rcx
	lea	(%r11, %rcx), %rcx
	jmp	*%rcx

	.p2align 4
LABEL(strncpy_exitz):
	mov	%rdi, %rax
	ret
#endif

	.p2align 4
LABEL(AMD_exit):
	test	%dl, %dl
	jz	LABEL(AMD_exit_more_8)
	test	$0x01, %dl
	jnz	LABEL(tail_0)
	test	$0x02, %dl
	jnz	LABEL(tail_1)
	test	$0x04, %dl
	jnz	LABEL(tail_2)
	test	$0x08, %dl
	jnz	LABEL(tail_3)
	test	$0x10, %dl
	jnz	LABEL(tail_4)
	test	$0x20, %dl
	jnz	LABEL(tail_5)
	test	$0x40, %dl
	jnz	LABEL(tail_6)

	.p2align 4
LABEL(tail_7):				/* 8 bytes */
	mov	(%rsi), %rcx
	mov	%rcx, (%rdi)
#ifdef USE_AS_STRNCPY
	mov	$8, %cl
	sub	$8, %r8
	jnz	LABEL(strncpy_fill_tail)
#endif
	ret

#ifdef USE_AS_STRNCPY
	/*
	 * Null terminated src string shorter than count. Fill the rest of the
	 * destination with null chars.
	 */
	.p2align 4
LABEL(strncpy_fill_tail):
	mov	%rax, %rdx
	movzx	%cl, %rax
	mov	%r8, %rcx
	add	%rax, %rdi
	xor	%eax, %eax
	shr	$3, %ecx
	jz	LABEL(strncpy_fill_less_8)

	rep	stosq
LABEL(strncpy_fill_less_8):
	mov	%r8, %rcx
	and	$7, %rcx
	jz	LABEL(strncpy_fill_return)
LABEL(strncpy_fill_less_7):
	sub	$1, %ecx
	mov	%al, (%rdi, %rcx)
	jnz	LABEL(strncpy_fill_less_7)
LABEL(strncpy_fill_return):
	mov	%rdx, %rax
	ret
#endif

	.p2align 4
LABEL(tail_0):				/* 1 byte */
	mov	(%rsi), %cl
	mov	%cl, (%rdi)
#ifdef USE_AS_STRNCPY
	mov	$1, %cl
	sub	$1, %r8
	jnz	LABEL(strncpy_fill_tail)
#endif
	ret

	.p2align 4
LABEL(tail_1):				/* 2 bytes */
	mov	(%rsi), %cx
	mov	%cx, (%rdi)
#ifdef USE_AS_STRNCPY
	mov	$2, %cl
	sub	$2, %r8
	jnz	LABEL(strncpy_fill_tail)
#endif
	ret

	.p2align 4
LABEL(tail_2):				/* 3 bytes */
	mov	(%rsi), %cx
	mov	%cx, (%rdi)
	mov	1(%rsi), %cx
	mov	%cx, 1(%rdi)
#ifdef USE_AS_STRNCPY
	mov	$3, %cl
	sub	$3, %r8
	jnz	LABEL(strncpy_fill_tail)
#endif
	ret

	.p2align 4
LABEL(tail_3):				/* 4 bytes */
	mov	(%rsi), %ecx
	mov	%ecx, (%rdi)
#ifdef USE_AS_STRNCPY
	mov	$4, %cl
	sub	$4, %r8
	jnz	LABEL(strncpy_fill_tail)
#endif
	ret

	.p2align 4
LABEL(tail_4):				/* 5 bytes */
	mov	(%rsi), %ecx
	mov	%ecx, (%rdi)
	mov	1(%rsi), %edx
	mov	%edx, 1(%rdi)
#ifdef USE_AS_STRNCPY
	mov	$5, %cl
	sub	$5, %r8
	jnz	LABEL(strncpy_fill_tail)
#endif
	ret

	.p2align 4
LABEL(tail_5):				/* 6 bytes */
	mov	(%rsi), %ecx
	mov	%ecx, (%rdi)
	mov	2(%rsi), %edx
	mov	%edx, 2(%rdi)
#ifdef USE_AS_STRNCPY
	mov	$6, %cl
	sub	$6, %r8
	jnz	LABEL(strncpy_fill_tail)
#endif
	ret

	.p2align 4
LABEL(tail_6):				/* 7 bytes */
	mov	(%rsi), %ecx
	mov	%ecx, (%rdi)
	mov	3(%rsi), %edx
	mov	%edx,3(%rdi)
#ifdef USE_AS_STRNCPY
	mov	$7, %cl
	sub	$7, %r8
	jnz	LABEL(strncpy_fill_tail)
#endif
	ret

	.p2align 4
LABEL(tail_8):				/* 9 bytes */
	mov	(%rsi), %rcx
	mov	%rcx, (%rdi)
	mov	5(%rsi), %edx
	mov	%edx, 5(%rdi)
#ifdef USE_AS_STRNCPY
	mov	$9, %cl
	sub	$9, %r8
	jnz	LABEL(strncpy_fill_tail)
#endif
	ret

	.p2align 4
LABEL(AMD_exit_more_8):
	test	%dh, %dh
	jz	LABEL(AMD_exit_more_16)
	test	$0x01, %dh
	jnz	LABEL(tail_8)
	test	$0x02, %dh
	jnz	LABEL(tail_9)
	test	$0x04, %dh
	jnz	LABEL(tail_10)
	test	$0x08, %dh
	jnz	LABEL(tail_11)
	test	$0x10, %dh
	jnz	LABEL(tail_12)
	test	$0x20, %dh
	jnz	LABEL(tail_13)
	test	$0x40, %dh
	jnz	LABEL(tail_14)

	.p2align 4
LABEL(tail_15):				/* 16 bytes */
	mov	(%rsi), %rcx
	mov	%rcx, (%rdi)
	mov	8(%rsi), %rdx
	mov	%rdx, 8(%rdi)
#ifdef USE_AS_STRNCPY
	mov	$16, %cl
	sub	$16, %r8
	jnz	LABEL(strncpy_fill_tail)
#endif
	ret

	.p2align 4
LABEL(tail_9):				/* 10 bytes */
	mov	(%rsi), %rcx
	mov	%rcx, (%rdi)
	mov	6(%rsi), %edx
	mov	%edx, 6(%rdi)
#ifdef USE_AS_STRNCPY
	mov	$10, %cl
	sub	$10, %r8
	jnz	LABEL(strncpy_fill_tail)
#endif
	ret

	.p2align 4
LABEL(tail_10):				/* 11 bytes */
	mov	(%rsi), %rcx
	mov	%rcx, (%rdi)
	mov	7(%rsi), %edx
	mov	%edx, 7(%rdi)
#ifdef USE_AS_STRNCPY
	mov	$11, %cl
	sub	$11, %r8
	jnz	LABEL(strncpy_fill_tail)
#endif
	ret

	.p2align 4
LABEL(tail_11):				/* 12 bytes */
	mov	(%rsi), %rcx
	mov	%rcx, (%rdi)
	mov	8(%rsi), %edx
	mov	%edx, 8(%rdi)
#ifdef USE_AS_STRNCPY
	mov	$12, %cl
	sub	$12, %r8
	jnz	LABEL(strncpy_fill_tail)
#endif
	ret

	.p2align 4
LABEL(tail_12):				/* 13 bytes */
	mov	(%rsi), %rcx
	mov	%rcx, (%rdi)
	mov	5(%rsi), %rcx
	mov	%rcx, 5(%rdi)
#ifdef USE_AS_STRNCPY
	mov	$13, %cl
	sub	$13, %r8
	jnz	LABEL(strncpy_fill_tail)
#endif
	ret

	.p2align 4
LABEL(tail_13):				/* 14 bytes */
	mov	(%rsi), %rcx
	mov	%rcx, (%rdi)
	mov	6(%rsi), %rcx
	mov	%rcx, 6(%rdi)
#ifdef USE_AS_STRNCPY
	mov	$14, %cl
	sub	$14, %r8
	jnz	LABEL(strncpy_fill_tail)
#endif
	ret

	.p2align 4
LABEL(tail_14):				/* 15 bytes */
	mov	(%rsi), %rcx
	mov	%rcx, (%rdi)
	mov	7(%rsi), %rcx
	mov	%rcx, 7(%rdi)
#ifdef USE_AS_STRNCPY
	mov	$15, %cl
	sub	$15, %r8
	jnz	LABEL(strncpy_fill_tail)
#endif
	ret

	.p2align 4
LABEL(AMD_exit_more_16):
	shr	$16, %edx
	test	%dl, %dl
	jz	LABEL(AMD_exit_more_24)
	test	$0x01, %dl
	jnz	LABEL(tail_16)
	test	$0x02, %dl
	jnz	LABEL(tail_17)
	test	$0x04, %dl
	jnz	LABEL(tail_18)
	test	$0x08, %dl
	jnz	LABEL(tail_19)
	test	$0x10, %dl
	jnz	LABEL(tail_20)
	test	$0x20, %dl
	jnz	LABEL(tail_21)
	test	$0x40, %dl
	jnz	LABEL(tail_22)

	.p2align 4
LABEL(tail_23):				/* 24 bytes */
	mov	(%rsi), %rcx
	mov	%rcx, (%rdi)
	mov	8(%rsi), %rdx
	mov	%rdx, 8(%rdi)
	mov	16(%rsi), %rcx
	mov	%rcx, 16(%rdi)
#ifdef USE_AS_STRNCPY
	mov	$24, %cl
	sub	$24, %r8
	jnz	LABEL(strncpy_fill_tail)
#endif
	ret

	.p2align 4
LABEL(tail_16):				/* 17 bytes */
	mov	(%rsi), %rcx
	mov	%rcx, (%rdi)
	mov	8(%rsi), %rdx
	mov	%rdx, 8(%rdi)
	mov	16(%rsi), %cl
	mov	%cl, 16(%rdi)
#ifdef USE_AS_STRNCPY
	mov	$17, %cl
	sub	$17, %r8
	jnz	LABEL(strncpy_fill_tail)
#endif
	ret

	.p2align 4
LABEL(tail_17):				/* 18 bytes */
	mov	(%rsi), %rcx
	mov	%rcx, (%rdi)
	mov	8(%rsi), %rdx
	mov	%rdx, 8(%rdi)
	mov	16(%rsi), %cx
	mov	%cx, 16(%rdi)
#ifdef USE_AS_STRNCPY
	mov	$18, %cl
	sub	$18, %r8
	jnz	LABEL(strncpy_fill_tail)
#endif
	ret

	.p2align 4
LABEL(tail_18):				/* 19 bytes */
	mov	(%rsi), %rcx
	mov	%rcx, (%rdi)
	mov	8(%rsi), %rdx
	mov	%rdx, 8(%rdi)
	mov	15(%rsi), %ecx
	mov	%ecx,15(%rdi)
#ifdef USE_AS_STRNCPY
	mov	$19, %cl
	sub	$19, %r8
	jnz	LABEL(strncpy_fill_tail)
#endif
	ret

	.p2align 4
LABEL(tail_19):				/* 20 bytes */
	mov	(%rsi), %rcx
	mov	%rcx, (%rdi)
	mov	8(%rsi), %rdx
	mov	%rdx, 8(%rdi)
	mov	16(%rsi), %ecx
	mov	%ecx, 16(%rdi)
#ifdef USE_AS_STRNCPY
	mov	$20, %cl
	sub	$20, %r8
	jnz	LABEL(strncpy_fill_tail)
#endif
	ret

	.p2align 4
LABEL(tail_20):				/* 21 bytes */
	mov	(%rsi), %rcx
	mov	%rcx, (%rdi)
	mov	8(%rsi), %rdx
	mov	%rdx, 8(%rdi)
	mov	13(%rsi), %rcx
	mov	%rcx, 13(%rdi)
#ifdef USE_AS_STRNCPY
	mov	$21, %cl
	sub	$21, %r8
	jnz	LABEL(strncpy_fill_tail)
#endif
	ret

	.p2align 4
LABEL(tail_21):				/* 22 bytes */
	mov	(%rsi), %rcx
	mov	%rcx, (%rdi)
	mov	8(%rsi), %rdx
	mov	%rdx, 8(%rdi)
	mov	14(%rsi), %rcx
	mov	%rcx, 14(%rdi)
#ifdef USE_AS_STRNCPY
	mov	$22, %cl
	sub	$22, %r8
	jnz	LABEL(strncpy_fill_tail)
#endif
	ret

	.p2align 4
LABEL(tail_22):				/* 23 bytes */
	mov	(%rsi), %rcx
	mov	%rcx, (%rdi)
	mov	8(%rsi), %rdx
	mov	%rdx, 8(%rdi)
	mov	15(%rsi), %rcx
	mov	%rcx, 15(%rdi)
#ifdef USE_AS_STRNCPY
	mov	$23, %cl
	sub	$23, %r8
	jnz	LABEL(strncpy_fill_tail)
#endif
	ret

	.p2align 4
LABEL(AMD_exit_more_24):
	test	$0x01, %dh
	jnz	LABEL(tail_24)
	test	$0x02, %dh
	jnz	LABEL(tail_25)
	test	$0x04, %dh
	jnz	LABEL(tail_26)
	test	$0x08, %dh
	jnz	LABEL(tail_27)
	test	$0x10, %dh
	jnz	LABEL(tail_28)
	test	$0x20, %dh
	jnz	LABEL(tail_29)
	test	$0x40, %dh
	jnz	LABEL(tail_30)

	.p2align 4
LABEL(tail_31):				/* 32 bytes */
	mov	(%rsi), %rcx
	mov	%rcx, (%rdi)
	mov	8(%rsi), %rdx
	mov	%rdx, 8(%rdi)
	mov	16(%rsi), %rcx
	mov	%rcx, 16(%rdi)
	mov	24(%rsi), %rdx
	mov	%rdx, 24(%rdi)
#ifdef USE_AS_STRNCPY
	mov	$32, %cl
	sub	$32, %r8
	jnz	LABEL(strncpy_fill_tail)
#endif
	ret

	.p2align 4
LABEL(tail_24):				/* 25 bytes */
	mov	(%rsi), %rcx
	mov	%rcx, (%rdi)
	mov	8(%rsi), %rdx
	mov	%rdx, 8(%rdi)
	mov	16(%rsi), %rcx
	mov	%rcx, 16(%rdi)
	mov	21(%rsi), %edx
	mov	%edx, 21(%rdi)
#ifdef USE_AS_STRNCPY
	mov	$25, %cl
	sub	$25, %r8
	jnz	LABEL(strncpy_fill_tail)
#endif
	ret

	.p2align 4
LABEL(tail_25):				/* 26 bytes */
	mov	(%rsi), %rcx
	mov	%rcx, (%rdi)
	mov	8(%rsi), %rdx
	mov	%rdx, 8(%rdi)
	mov	16(%rsi), %rcx
	mov	%rcx, 16(%rdi)
	mov	22(%rsi), %edx
	mov	%edx, 22(%rdi)
#ifdef USE_AS_STRNCPY
	mov	$26, %cl
	sub	$26, %r8
	jnz	LABEL(strncpy_fill_tail)
#endif
	ret

	.p2align 4
LABEL(tail_26):				/* 27 bytes */
	mov	(%rsi), %rcx
	mov	%rcx, (%rdi)
	mov	8(%rsi), %rdx
	mov	%rdx, 8(%rdi)
	mov	16(%rsi), %rcx
	mov	%rcx, 16(%rdi)
	mov	23(%rsi), %edx
	mov	%edx, 23(%rdi)
#ifdef USE_AS_STRNCPY
	mov	$27, %cl
	sub	$27, %r8
	jnz	LABEL(strncpy_fill_tail)
#endif
	ret

	.p2align 4
LABEL(tail_27):				/* 28 bytes */
	mov	(%rsi), %rcx
	mov	%rcx, (%rdi)
	mov	8(%rsi), %rdx
	mov	%rdx, 8(%rdi)
	mov	16(%rsi), %rcx
	mov	%rcx, 16(%rdi)
	mov	24(%rsi), %edx
	mov	%edx, 24(%rdi)
#ifdef USE_AS_STRNCPY
	mov	$28, %cl
	sub	$28, %r8
	jnz	LABEL(strncpy_fill_tail)
#endif
	ret

	.p2align 4
LABEL(tail_28):				/* 29 bytes */
	mov	(%rsi), %rcx
	mov	%rcx, (%rdi)
	mov	8(%rsi), %rdx
	mov	%rdx, 8(%rdi)
	mov	16(%rsi), %rcx
	mov	%rcx, 16(%rdi)
	mov	21(%rsi), %rdx
	mov	%rdx, 21(%rdi)
#ifdef USE_AS_STRNCPY
	mov	$29, %cl
	sub	$29, %r8
	jnz	LABEL(strncpy_fill_tail)
#endif
	ret

	.p2align 4
LABEL(tail_29):				/* 30 bytes */
	mov	(%rsi), %rcx
	mov	%rcx, (%rdi)
	mov	8(%rsi), %rdx
	mov	%rdx, 8(%rdi)
	mov	16(%rsi), %rcx
	mov	%rcx, 16(%rdi)
	mov	22(%rsi), %rdx
	mov	%rdx, 22(%rdi)
#ifdef USE_AS_STRNCPY
	mov	$30, %cl
	sub	$30, %r8
	jnz	LABEL(strncpy_fill_tail)
#endif
	ret

	.p2align 4
LABEL(tail_30):				/* 31 bytes */
	mov	(%rsi), %rcx
	mov	%rcx, (%rdi)
	mov	8(%rsi), %rdx
	mov	%rdx, 8(%rdi)
	mov	16(%rsi), %rcx
	mov	%rcx, 16(%rdi)
	mov	23(%rsi), %rdx
	mov	%rdx, 23(%rdi)
#ifdef USE_AS_STRNCPY
	mov	$31, %cl
	sub	$31, %r8
	jnz	LABEL(strncpy_fill_tail)
#endif
	ret

	.pushsection .rodata
	.p2align 4
LABEL(tail_table):
	.int	LABEL(tail_0) - LABEL(tail_table)	/* 1 byte */
	.int	LABEL(tail_1) - LABEL(tail_table)
	.int	LABEL(tail_2) - LABEL(tail_table)
	.int	LABEL(tail_3) - LABEL(tail_table)
	.int	LABEL(tail_4) - LABEL(tail_table)
	.int	LABEL(tail_5) - LABEL(tail_table)
	.int	LABEL(tail_6) - LABEL(tail_table)
	.int	LABEL(tail_7) - LABEL(tail_table)
	.int	LABEL(tail_8) - LABEL(tail_table)
	.int	LABEL(tail_9) - LABEL(tail_table)
	.int	LABEL(tail_10) - LABEL(tail_table)
	.int	LABEL(tail_11) - LABEL(tail_table)
	.int	LABEL(tail_12) - LABEL(tail_table)
	.int	LABEL(tail_13) - LABEL(tail_table)
	.int	LABEL(tail_14) - LABEL(tail_table)
	.int	LABEL(tail_15) - LABEL(tail_table)
	.int	LABEL(tail_16) - LABEL(tail_table)
	.int	LABEL(tail_17) - LABEL(tail_table)
	.int	LABEL(tail_18) - LABEL(tail_table)
	.int	LABEL(tail_19) - LABEL(tail_table)
	.int	LABEL(tail_20) - LABEL(tail_table)
	.int	LABEL(tail_21) - LABEL(tail_table)
	.int	LABEL(tail_22) - LABEL(tail_table)
	.int	LABEL(tail_23) - LABEL(tail_table)
	.int	LABEL(tail_24) - LABEL(tail_table)
	.int	LABEL(tail_25) - LABEL(tail_table)
	.int	LABEL(tail_26) - LABEL(tail_table)
	.int	LABEL(tail_27) - LABEL(tail_table)
	.int	LABEL(tail_28) - LABEL(tail_table)
	.int	LABEL(tail_29) - LABEL(tail_table)
	.int	LABEL(tail_30) - LABEL(tail_table)
	.int	LABEL(tail_31) - LABEL(tail_table)	/* 32 bytes */

	.p2align 4
LABEL(unaligned_table):
	.int	LABEL(ashr_0) - LABEL(unaligned_table)
	.int	LABEL(ashr_1) - LABEL(unaligned_table)
	.int	LABEL(ashr_2) - LABEL(unaligned_table)
	.int	LABEL(ashr_3) - LABEL(unaligned_table)
	.int	LABEL(ashr_4) - LABEL(unaligned_table)
	.int	LABEL(ashr_5) - LABEL(unaligned_table)
	.int	LABEL(ashr_6) - LABEL(unaligned_table)
	.int	LABEL(ashr_7) - LABEL(unaligned_table)
	.int	LABEL(ashr_8) - LABEL(unaligned_table)
	.int	LABEL(ashr_9) - LABEL(unaligned_table)
	.int	LABEL(ashr_10) - LABEL(unaligned_table)
	.int	LABEL(ashr_11) - LABEL(unaligned_table)
	.int	LABEL(ashr_12) - LABEL(unaligned_table)
	.int	LABEL(ashr_13) - LABEL(unaligned_table)
	.int	LABEL(ashr_14) - LABEL(unaligned_table)
	.int	LABEL(ashr_15) - LABEL(unaligned_table)
	.popsection

#ifdef USE_AS_STRNCPY
	SET_SIZE(strncpy)
#else
	SET_SIZE(strcpy)			/* (char *, const char *) */
#endif
