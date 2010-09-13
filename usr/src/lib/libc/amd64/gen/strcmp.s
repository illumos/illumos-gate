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
 *	str[n]cmp - compare chars between two string
 */

#include "SYS.h"
#include "proc64_id.h"

#define LABEL(s) .strcmp/**/s

#ifdef USE_AS_STRNCMP
	/*
	 * Since the counter, %r11, is unsigned, we branch to strcmp_exitz
	 * if the new counter > the old one or is 0. 
	 */
#define UPDATE_STRNCMP_COUNTER				\
	/* calculate left number to compare */		\
	lea	-16(%rcx, %r11), %r9;			\
	cmp	%r9, %r11;				\
	jb	LABEL(strcmp_exitz);			\
	test	%r9, %r9;				\
	je	LABEL(strcmp_exitz);			\
	mov	%r9, %r11
#else
#define UPDATE_STRNCMP_COUNTER
#endif

	/*
	 * This implementation uses SSE to compare up to 16 bytes at a time.
	 */
#ifdef USE_AS_STRNCMP
	ENTRY(strncmp)
	test	%rdx, %rdx
	je	LABEL(strcmp_exitz)
	mov	%rdx, %r11
#else
	ENTRY(strcmp)			/* (const char *, const char *) */
#endif
	mov	%esi, %ecx
	mov	%edi, %eax
	and	$0x3f, %rcx		/* rsi alignment in cache line */
	and	$0x3f, %rax		/* rdi alignment in cache line */
	cmp	$0x30, %ecx
	ja	LABEL(crosscache)	/* rsi: 16-byte load will cross cache line */
	cmp	$0x30, %eax
	ja	LABEL(crosscache)	/* rdi: 16-byte load will cross cache line */
	movlpd	(%rdi), %xmm1
	movlpd	(%rsi), %xmm2
	movhpd	8(%rdi), %xmm1
	movhpd	8(%rsi), %xmm2
	pxor	%xmm0, %xmm0		/* clear %xmm0 for null char checks */
	pcmpeqb	%xmm1, %xmm0		/* Any null chars? */
	pcmpeqb	%xmm2, %xmm1		/* compare first 16 bytes for equality */
	psubb	%xmm0, %xmm1		/* packed sub of comparison results*/
	pmovmskb %xmm1, %edx
	sub	$0xffff, %edx		/* if first 16 bytes are same, edx == 0xffff */
	jnz	LABEL(less16bytes)	/* If not, found mismatch or null char */
#ifdef USE_AS_STRNCMP
	sub	$16, %r11
	jbe	LABEL(strcmp_exitz)	/* finish comparision */
#endif
	add	$16, %rsi		/* prepare to search next 16 bytes */
	add	$16, %rdi		/* prepare to search next 16 bytes */

	/*
	 * Determine rdi and rsi string offsets from 16-byte alignment.
	 * Use relative offset difference between the two to determine which case
	 * below to use.
	 */
	.p2align 4
LABEL(crosscache):
	and	$0xfffffffffffffff0, %rsi	/* force %rsi to be 16 byte aligned */
	and	$0xfffffffffffffff0, %rdi	/* force %rdi to be 16 byte aligned */
	mov	$0xffff, %edx			/* for equivalent offset */
	xor	%r8d, %r8d
	and	$0xf, %ecx			/* offset of rsi */
	and	$0xf, %eax			/* offset of rdi */
	cmp	%eax, %ecx
	je	LABEL(ashr_0)			/* both strings have the same alignment */
	ja	LABEL(bigger)
	mov	%edx, %r8d			/* r8d is offset flag for exit tail */
	xchg	%ecx, %eax
	xchg	%rsi, %rdi
LABEL(bigger):
	mov	%rcx, %r9
	sub	%rax, %r9
	lea	LABEL(unaligned_table)(%rip), %r10
	movslq	(%r10, %r9, 4), %r9
	lea	(%r10, %r9), %r10
	jmp	*%r10				/* jump to corresponding case */

/*
 * ashr_0 handles the following cases:
 * 	str1 offset = str2 offset
 */
	.p2align 4
LABEL(ashr_0):
	movdqa	(%rsi), %xmm1
	pxor	%xmm0, %xmm0			/* clear %xmm0 for null char check */
	pcmpeqb	%xmm1, %xmm0			/* Any null chars? */
	pcmpeqb	(%rdi), %xmm1			/* compare 16 bytes for equality */
	psubb	%xmm0, %xmm1			/* packed sub of comparison results*/
	pmovmskb %xmm1, %r9d
	shr	%cl, %edx			/* adjust 0xffff for offset */
	shr	%cl, %r9d			/* adjust for 16-byte offset */
	sub	%r9d, %edx
	/*
	 * edx must be the same with r9d if in left byte (16-rcx) is equal to
	 * the start from (16-rax) and no null char was seen.
	 */
	jne	LABEL(less32bytes)		/* mismatch or null char */
	UPDATE_STRNCMP_COUNTER
	mov	$16, %rcx
	mov	$16, %r9
	pxor	%xmm0, %xmm0			/* clear xmm0, may have changed above */

	/*
	 * Now both strings are aligned at 16-byte boundary. Loop over strings
	 * checking 32-bytes per iteration.
	 */
	.p2align 4
LABEL(loop_ashr_0):
	movdqa	(%rsi, %rcx), %xmm1
	movdqa	(%rdi, %rcx), %xmm2

	pcmpeqb	%xmm1, %xmm0
	pcmpeqb	%xmm2, %xmm1
	psubb	%xmm0, %xmm1
	pmovmskb %xmm1, %edx
	sub	$0xffff, %edx
	jnz	LABEL(exit)		/* mismatch or null char seen */

#ifdef USE_AS_STRNCMP
	sub	$16, %r11
	jbe	LABEL(strcmp_exitz)
#endif
	add	$16, %rcx
	movdqa	(%rsi, %rcx), %xmm1
	movdqa	(%rdi, %rcx), %xmm2

	pcmpeqb	%xmm1, %xmm0
	pcmpeqb	%xmm2, %xmm1
	psubb	%xmm0, %xmm1
	pmovmskb %xmm1, %edx
	sub	$0xffff, %edx
	jnz	LABEL(exit)
#ifdef USE_AS_STRNCMP
	sub	$16, %r11
	jbe	LABEL(strcmp_exitz)
#endif
	add	$16, %rcx
	jmp	LABEL(loop_ashr_0)

/*
 * ashr_1 handles the following cases: 
 * 	abs(str1 offset - str2 offset) = 15
 */
	.p2align 4
LABEL(ashr_1):
	pxor	%xmm0, %xmm0
	movdqa	(%rdi), %xmm2
	movdqa	(%rsi), %xmm1
	pcmpeqb	%xmm1, %xmm0		/* Any null chars? */
	pslldq	$15, %xmm2		/* shift first string to align with second */	
	pcmpeqb	%xmm1, %xmm2		/* compare 16 bytes for equality */
	psubb	%xmm0, %xmm2		/* packed sub of comparison results*/
	pmovmskb %xmm2, %r9d
	shr	%cl, %edx		/* adjust 0xffff for offset */
	shr	%cl, %r9d		/* adjust for 16-byte offset */
	sub	%r9d, %edx
	jnz	LABEL(less32bytes)	/* mismatch or null char seen */
	movdqa	(%rdi), %xmm3
	UPDATE_STRNCMP_COUNTER

	pxor	%xmm0, %xmm0
	mov	$16, %rcx		/* index for loads */	
	mov	$1, %r9d		/* rdi bytes already examined. Used in exit code */
	/*
	 * Setup %r10 value allows us to detect crossing a page boundary.
	 * When %r10 goes positive we are crossing a page boundary and
	 * need to do a nibble.
	 */
	lea	1(%rdi), %r10	 
	and	$0xfff, %r10		/* offset into 4K page */
	sub	$0x1000, %r10		/* subtract 4K pagesize */
	movdqa	%xmm3, %xmm4

	.p2align 4
LABEL(loop_ashr_1):
	add	$16, %r10
	jg	LABEL(nibble_ashr_1)	/* cross page boundary */	

LABEL(gobble_ashr_1):
	movdqa	(%rsi, %rcx), %xmm1
	movdqa	(%rdi, %rcx), %xmm2
	movdqa	%xmm2, %xmm4		 /* store for next cycle */

	psrldq	$1, %xmm3		
	pslldq	$15, %xmm2		
	por	%xmm3, %xmm2		/* merge into one 16byte value */

	pcmpeqb	%xmm1, %xmm0	
	pcmpeqb	%xmm2, %xmm1
	psubb	%xmm0, %xmm1
	pmovmskb %xmm1, %edx
	sub	$0xffff, %edx
	jnz	LABEL(exit)

#ifdef USE_AS_STRNCMP
	sub	$16, %r11
	jbe	LABEL(strcmp_exitz)
#endif
	add	$16, %rcx
	movdqa	%xmm4, %xmm3	

	add	$16, %r10
	jg	LABEL(nibble_ashr_1)	/* cross page boundary */	

	movdqa	(%rsi, %rcx), %xmm1
	movdqa	(%rdi, %rcx), %xmm2
	movdqa	%xmm2, %xmm4		/* store for next cycle */

	psrldq	$1, %xmm3			
	pslldq 	$15, %xmm2		
	por	%xmm3, %xmm2		/* merge into one 16byte value */

	pcmpeqb	%xmm1, %xmm0
	pcmpeqb	%xmm2, %xmm1
	psubb	%xmm0, %xmm1
	pmovmskb %xmm1, %edx
	sub	$0xffff, %edx
	jnz	LABEL(exit)

#ifdef USE_AS_STRNCMP
	sub	$16, %r11
	jbe	LABEL(strcmp_exitz)
#endif
	add	$16, %rcx
	movdqa	%xmm4, %xmm3		
	jmp	LABEL(loop_ashr_1)		

	/*
	 * Nibble avoids loads across page boundary. This is to avoid a potential
	 * access into unmapped memory.
	 */
	.p2align 4
LABEL(nibble_ashr_1):
	psrldq	$1, %xmm4		
	movdqa	(%rsi, %rcx), %xmm1
	pcmpeqb	%xmm1, %xmm0
	pcmpeqb	%xmm4, %xmm1
	psubb	%xmm0, %xmm1
	pmovmskb %xmm1, %edx
	sub	$0x7fff, %edx
	jnz	LABEL(exit)
#ifdef USE_AS_STRNCMP
	cmp	$15, %r11
	jbe	LABEL(strcmp_exitz)
#endif
	pxor	%xmm0, %xmm0
	sub	$0x1000, %r10		/* subtract 4K from %r10 */
	jmp	LABEL(gobble_ashr_1)	

/*
 * ashr_2 handles the following cases: 
 * 	abs(str1 offset - str2 offset) = 14
 */
	.p2align 4
LABEL(ashr_2):
	pxor	%xmm0, %xmm0
	movdqa	(%rdi), %xmm2
	movdqa	(%rsi), %xmm1
	pcmpeqb	%xmm1, %xmm0
	pslldq	$14, %xmm2		
	pcmpeqb	%xmm1, %xmm2
	psubb	%xmm0, %xmm2
	pmovmskb %xmm2, %r9d
	shr	%cl, %edx
	shr	%cl, %r9d
	sub	%r9d, %edx
	jnz	LABEL(less32bytes)
	movdqa	(%rdi), %xmm3
	UPDATE_STRNCMP_COUNTER

	pxor	%xmm0, %xmm0
	mov	$16, %rcx	/* index for loads */
	mov	$2, %r9d	/* rdi bytes already examined. Used in exit code */
	/*
	 * Setup %r10 value allows us to detect crossing a page boundary.
	 * When %r10 goes positive we are crossing a page boundary and
	 * need to do a nibble.
	 */
	lea	2(%rdi), %r10	 
	and	$0xfff, %r10	/* offset into 4K page */
	sub	$0x1000, %r10	/* subtract 4K pagesize */
	movdqa	%xmm3, %xmm4

	.p2align 4
LABEL(loop_ashr_2):
	add	$16, %r10
	jg	LABEL(nibble_ashr_2)	

LABEL(gobble_ashr_2):
	movdqa	(%rsi, %rcx), %xmm1
	movdqa	(%rdi, %rcx), %xmm2
	movdqa	%xmm2, %xmm4

	psrldq	$2, %xmm3		
	pslldq	$14, %xmm2		
	por	%xmm3, %xmm2

	pcmpeqb	%xmm1, %xmm0	
	pcmpeqb	%xmm2, %xmm1
	psubb	%xmm0, %xmm1
	pmovmskb %xmm1, %edx
	sub	$0xffff, %edx
	jnz	LABEL(exit)

#ifdef USE_AS_STRNCMP
	sub	$16, %r11
	jbe	LABEL(strcmp_exitz)
#endif

	add	$16, %rcx
	movdqa	%xmm4, %xmm3

	add	$16, %r10
	jg	LABEL(nibble_ashr_2)	/* cross page boundary */

	movdqa	(%rsi, %rcx), %xmm1
	movdqa	(%rdi, %rcx), %xmm2
	movdqa	%xmm2, %xmm4

	psrldq	$2, %xmm3			
	pslldq 	$14, %xmm2		
	por	%xmm3, %xmm2

	pcmpeqb	%xmm1, %xmm0
	pcmpeqb	%xmm2, %xmm1
	psubb	%xmm0, %xmm1
	pmovmskb %xmm1, %edx
	sub	$0xffff, %edx
	jnz	LABEL(exit)

#ifdef USE_AS_STRNCMP
	sub	$16, %r11
	jbe	LABEL(strcmp_exitz)
#endif

	add	$16, %rcx
	movdqa	%xmm4, %xmm3	
	jmp	LABEL(loop_ashr_2)		

	.p2align 4
LABEL(nibble_ashr_2):
	psrldq	$2, %xmm4		
	movdqa	(%rsi, %rcx), %xmm1
	pcmpeqb	%xmm1, %xmm0
	pcmpeqb	%xmm4, %xmm1
	psubb	%xmm0, %xmm1
	pmovmskb %xmm1, %edx
	sub	$0x3fff, %edx
	jnz	LABEL(exit)
#ifdef USE_AS_STRNCMP
	cmp	$14, %r11
	jbe	LABEL(strcmp_exitz)
#endif
	pxor	%xmm0, %xmm0
	sub	$0x1000, %r10		/* subtract 4K from %r10 */
	jmp	LABEL(gobble_ashr_2)	

/*
 * ashr_3 handles the following cases: 
 * 	abs(str1 offset - str2 offset) = 13
 */
	.p2align 4
LABEL(ashr_3):
	pxor	%xmm0, %xmm0
	movdqa	(%rdi), %xmm2
	movdqa	(%rsi), %xmm1
	pcmpeqb	%xmm1, %xmm0
	pslldq	$13, %xmm2		
	pcmpeqb	%xmm1, %xmm2
	psubb	%xmm0, %xmm2
	pmovmskb %xmm2, %r9d
	shr	%cl, %edx
	shr	%cl, %r9d
	sub	%r9d, %edx
	jnz	LABEL(less32bytes)
	movdqa	(%rdi), %xmm3

	UPDATE_STRNCMP_COUNTER

	pxor	%xmm0, %xmm0
	mov	$16, %rcx	/* index for loads */
	mov	$3, %r9d	/* rdi bytes already examined. Used in exit code */
	/*
	 * Setup %r10 value allows us to detect crossing a page boundary.
	 * When %r10 goes positive we are crossing a page boundary and
	 * need to do a nibble.
	 */
	lea	3(%rdi), %r10	 
	and	$0xfff, %r10	/* offset into 4K page */
	sub	$0x1000, %r10	/* subtract 4K pagesize */
	movdqa	%xmm3, %xmm4

	.p2align 4
LABEL(loop_ashr_3):
	add	$16, %r10
	jg	LABEL(nibble_ashr_3)	

LABEL(gobble_ashr_3):
	movdqa	(%rsi, %rcx), %xmm1
	movdqa	(%rdi, %rcx), %xmm2
	movdqa	%xmm2, %xmm4

	psrldq	$3, %xmm3		
	pslldq	$13, %xmm2		
	por	%xmm3, %xmm2

	pcmpeqb	%xmm1, %xmm0
	pcmpeqb	%xmm2, %xmm1
	psubb	%xmm0, %xmm1
	pmovmskb %xmm1, %edx
	sub	$0xffff, %edx
	jnz	LABEL(exit)

#ifdef USE_AS_STRNCMP
	sub	$16, %r11
	jbe	LABEL(strcmp_exitz)
#endif

	add	$16, %rcx
	movdqa	%xmm4, %xmm3	

	add	$16, %r10
	jg	LABEL(nibble_ashr_3)	/* cross page boundary */

	movdqa	(%rsi, %rcx), %xmm1
	movdqa	(%rdi, %rcx), %xmm2
	movdqa	%xmm2, %xmm4

	psrldq	$3, %xmm3			
	pslldq 	$13, %xmm2		
	por	%xmm3, %xmm2

	pcmpeqb	%xmm1, %xmm0
	pcmpeqb	%xmm2, %xmm1
	psubb	%xmm0, %xmm1
	pmovmskb %xmm1, %edx
	sub	$0xffff, %edx
	jnz	LABEL(exit)

#ifdef USE_AS_STRNCMP
	sub	$16, %r11
	jbe	LABEL(strcmp_exitz)
#endif

	add	$16, %rcx
	movdqa	%xmm4, %xmm3
	jmp	LABEL(loop_ashr_3)		

	.p2align 4
LABEL(nibble_ashr_3):
	psrldq	$3, %xmm4		
	movdqa	(%rsi, %rcx), %xmm1
	pcmpeqb	%xmm1, %xmm0
	pcmpeqb	%xmm4, %xmm1
	psubb	%xmm0, %xmm1
	pmovmskb %xmm1, %edx
	sub	$0x1fff, %edx
	jnz	LABEL(exit)
#ifdef USE_AS_STRNCMP
	cmp	$13, %r11
	jbe	LABEL(strcmp_exitz)
#endif
	pxor	%xmm0, %xmm0
	sub	$0x1000, %r10		/* subtract 4K from %r10 */
	jmp	LABEL(gobble_ashr_3)	

/*
 * ashr_4 handles the following cases: 
 * 	abs(str1 offset - str2 offset) = 12
 */
	.p2align 4
LABEL(ashr_4):
	pxor	%xmm0, %xmm0
	movdqa	(%rdi), %xmm2
	movdqa	(%rsi), %xmm1
	pcmpeqb	%xmm1, %xmm0
	pslldq	$12, %xmm2		
	pcmpeqb	%xmm1, %xmm2
	psubb	%xmm0, %xmm2
	pmovmskb %xmm2, %r9d
	shr	%cl, %edx
	shr	%cl, %r9d
	sub	%r9d, %edx
	jnz	LABEL(less32bytes)
	movdqa	(%rdi), %xmm3

	UPDATE_STRNCMP_COUNTER

	pxor	%xmm0, %xmm0
	mov	$16, %rcx	/* index for loads */
	mov	$4, %r9d	/* rdi bytes already examined. Used in exit code */
	/*
	 * Setup %r10 value allows us to detect crossing a page boundary.
	 * When %r10 goes positive we are crossing a page boundary and
	 * need to do a nibble.
	 */
	lea	4(%rdi), %r10	 
	and	$0xfff, %r10	/* offset into 4K page */
	sub	$0x1000, %r10	/* subtract 4K pagesize */
	movdqa	%xmm3, %xmm4

	.p2align 4
LABEL(loop_ashr_4):
	add	$16, %r10
	jg	LABEL(nibble_ashr_4)	

LABEL(gobble_ashr_4):
	movdqa	(%rsi, %rcx), %xmm1
	movdqa	(%rdi, %rcx), %xmm2
	movdqa	%xmm2, %xmm4

	psrldq	$4, %xmm3		
	pslldq	$12, %xmm2		
	por	%xmm3, %xmm2

	pcmpeqb	%xmm1, %xmm0
	pcmpeqb	%xmm2, %xmm1
	psubb	%xmm0, %xmm1
	pmovmskb %xmm1, %edx
	sub	$0xffff, %edx
	jnz	LABEL(exit)

#ifdef USE_AS_STRNCMP
	sub	$16, %r11
	jbe	LABEL(strcmp_exitz)
#endif

	add	$16, %rcx
	movdqa	%xmm4, %xmm3

	add	$16, %r10
	jg	LABEL(nibble_ashr_4)	/* cross page boundary */

	movdqa	(%rsi, %rcx), %xmm1
	movdqa	(%rdi, %rcx), %xmm2
	movdqa	%xmm2, %xmm4

	psrldq	$4, %xmm3			
	pslldq 	$12, %xmm2		
	por	%xmm3, %xmm2

	pcmpeqb	%xmm1, %xmm0
	pcmpeqb	%xmm2, %xmm1
	psubb	%xmm0, %xmm1
	pmovmskb %xmm1, %edx
	sub	$0xffff, %edx
	jnz	LABEL(exit)

#ifdef USE_AS_STRNCMP
	sub	$16, %r11
	jbe	LABEL(strcmp_exitz)
#endif

	add	$16, %rcx
	movdqa	%xmm4, %xmm3
	jmp	LABEL(loop_ashr_4)		

	.p2align 4
LABEL(nibble_ashr_4):
	psrldq	$4, %xmm4		
	movdqa	(%rsi, %rcx), %xmm1
	pcmpeqb	%xmm1, %xmm0
	pcmpeqb	%xmm4, %xmm1
	psubb	%xmm0, %xmm1
	pmovmskb %xmm1, %edx
	sub	$0x0fff, %edx
	jnz	LABEL(exit)
#ifdef USE_AS_STRNCMP
	cmp	$12, %r11
	jbe	LABEL(strcmp_exitz)
#endif
	pxor	%xmm0, %xmm0
	sub	$0x1000, %r10		/* subtract 4K from %r10 */
	jmp	LABEL(gobble_ashr_4)	

/*
 * ashr_5 handles the following cases: 
 * 	abs(str1 offset - str2 offset) = 11
 */
	.p2align 4
LABEL(ashr_5):
	pxor	%xmm0, %xmm0
	movdqa	(%rdi), %xmm2
	movdqa	(%rsi), %xmm1
	pcmpeqb	%xmm1, %xmm0
	pslldq	$11, %xmm2		
	pcmpeqb	%xmm1, %xmm2
	psubb	%xmm0, %xmm2
	pmovmskb %xmm2, %r9d
	shr	%cl, %edx
	shr	%cl, %r9d
	sub	%r9d, %edx
	jnz	LABEL(less32bytes)
	movdqa	(%rdi), %xmm3

	UPDATE_STRNCMP_COUNTER

	pxor	%xmm0, %xmm0
	mov	$16, %rcx	/* index for loads */
	mov	$5, %r9d	/* rdi bytes already examined. Used in exit code */
	/*
	 * Setup %r10 value allows us to detect crossing a page boundary.
	 * When %r10 goes positive we are crossing a page boundary and
	 * need to do a nibble.
	 */
	lea	5(%rdi), %r10	 
	and	$0xfff, %r10	/* offset into 4K page */
	sub	$0x1000, %r10	/* subtract 4K pagesize */
	movdqa	%xmm3, %xmm4

	.p2align 4
LABEL(loop_ashr_5):
	add	$16, %r10
	jg	LABEL(nibble_ashr_5)	

LABEL(gobble_ashr_5):
	movdqa	(%rsi, %rcx), %xmm1
	movdqa	(%rdi, %rcx), %xmm2
	movdqa	%xmm2, %xmm4

	psrldq	$5, %xmm3		
	pslldq	$11, %xmm2		
	por	%xmm3, %xmm2

	pcmpeqb	%xmm1, %xmm0
	pcmpeqb	%xmm2, %xmm1
	psubb	%xmm0, %xmm1
	pmovmskb %xmm1, %edx
	sub	$0xffff, %edx
	jnz	LABEL(exit)

#ifdef USE_AS_STRNCMP
	sub	$16, %r11
	jbe	LABEL(strcmp_exitz)
#endif

	add	$16, %rcx
	movdqa	%xmm4, %xmm3

	add	$16, %r10
	jg	LABEL(nibble_ashr_5)	/* cross page boundary */

	movdqa	(%rsi, %rcx), %xmm1
	movdqa	(%rdi, %rcx), %xmm2
	movdqa	%xmm2, %xmm4

	psrldq	$5, %xmm3			
	pslldq 	$11, %xmm2		
	por	%xmm3, %xmm2

	pcmpeqb	%xmm1, %xmm0
	pcmpeqb	%xmm2, %xmm1
	psubb	%xmm0, %xmm1
	pmovmskb %xmm1, %edx
	sub	$0xffff, %edx
	jnz	LABEL(exit)

#ifdef USE_AS_STRNCMP
	sub	$16, %r11
	jbe	LABEL(strcmp_exitz)
#endif

	add	$16, %rcx
	movdqa	%xmm4, %xmm3
	jmp	LABEL(loop_ashr_5)		

	.p2align 4
LABEL(nibble_ashr_5):
	psrldq	$5, %xmm4		
	movdqa	(%rsi, %rcx), %xmm1
	pcmpeqb	%xmm1, %xmm0
	pcmpeqb	%xmm4, %xmm1
	psubb	%xmm0, %xmm1
	pmovmskb %xmm1, %edx
	sub	$0x07ff, %edx
	jnz	LABEL(exit)
#ifdef USE_AS_STRNCMP
	cmp	$11, %r11
	jbe	LABEL(strcmp_exitz)
#endif
 	pxor	%xmm0, %xmm0
	sub	$0x1000, %r10		/* subtract 4K from %r10 */
	jmp	LABEL(gobble_ashr_5)	

/*
 * ashr_6 handles the following cases: 
 * 	abs(str1 offset - str2 offset) = 10
 */
	.p2align 4
LABEL(ashr_6):
	pxor	%xmm0, %xmm0
	movdqa	(%rdi), %xmm2
	movdqa	(%rsi), %xmm1
	pcmpeqb	%xmm1, %xmm0
	pslldq	$10, %xmm2		
	pcmpeqb	%xmm1, %xmm2
	psubb	%xmm0, %xmm2
	pmovmskb %xmm2, %r9d
	shr	%cl, %edx
	shr	%cl, %r9d
	sub	%r9d, %edx
	jnz	LABEL(less32bytes)
	movdqa	(%rdi), %xmm3

	UPDATE_STRNCMP_COUNTER

	pxor	%xmm0, %xmm0
	mov	$16, %rcx	/* index for loads */
	mov	$6, %r9d	/* rdi bytes already examined. Used in exit code */
	/*
	 * Setup %r10 value allows us to detect crossing a page boundary.
	 * When %r10 goes positive we are crossing a page boundary and
	 * need to do a nibble.
	 */
	lea	6(%rdi), %r10	 
	and	$0xfff, %r10	/* offset into 4K page */
	sub	$0x1000, %r10	/* subtract 4K pagesize */
	movdqa	%xmm3, %xmm4

	.p2align 4
LABEL(loop_ashr_6):
	add	$16, %r10
	jg	LABEL(nibble_ashr_6)	

LABEL(gobble_ashr_6):
	movdqa	(%rsi, %rcx), %xmm1
	movdqa	(%rdi, %rcx), %xmm2
	movdqa	%xmm2, %xmm4

	psrldq	$6, %xmm3		
	pslldq	$10, %xmm2		
	por	%xmm3, %xmm2

	pcmpeqb	%xmm1, %xmm0
	pcmpeqb	%xmm2, %xmm1
	psubb	%xmm0, %xmm1
	pmovmskb %xmm1, %edx
	sub	$0xffff, %edx
	jnz	LABEL(exit)

#ifdef USE_AS_STRNCMP
	sub	$16, %r11
	jbe	LABEL(strcmp_exitz)
#endif

	add	$16, %rcx
	movdqa	%xmm4, %xmm3	

	add	$16, %r10
	jg	LABEL(nibble_ashr_6)	/* cross page boundary */

	movdqa	(%rsi, %rcx), %xmm1
	movdqa	(%rdi, %rcx), %xmm2
	movdqa	%xmm2, %xmm4

	psrldq	$6, %xmm3			
	pslldq 	$10, %xmm2		
	por	%xmm3, %xmm2

	pcmpeqb	%xmm1, %xmm0
	pcmpeqb	%xmm2, %xmm1
	psubb	%xmm0, %xmm1
	pmovmskb %xmm1, %edx
	sub	$0xffff, %edx
	jnz	LABEL(exit)

#ifdef USE_AS_STRNCMP
	sub	$16, %r11
	jbe	LABEL(strcmp_exitz)
#endif

	add	$16, %rcx
	movdqa	%xmm4, %xmm3	
	jmp	LABEL(loop_ashr_6)		

	.p2align 4
LABEL(nibble_ashr_6):
	psrldq	$6, %xmm4		
	movdqa	(%rsi, %rcx), %xmm1
	pcmpeqb	%xmm1, %xmm0
	pcmpeqb	%xmm4, %xmm1
	psubb	%xmm0, %xmm1
	pmovmskb %xmm1, %edx
	sub	$0x03ff, %edx
	jnz	LABEL(exit)
#ifdef USE_AS_STRNCMP
	cmp	$10, %r11
	jbe	LABEL(strcmp_exitz)
#endif
 	pxor	%xmm0, %xmm0
	sub	$0x1000, %r10		/* subtract 4K from %r10 */
	jmp	LABEL(gobble_ashr_6)	

/*
 * ashr_7 handles the following cases: 
 * 	abs(str1 offset - str2 offset) = 9
 */
	.p2align 4
LABEL(ashr_7):
	pxor	%xmm0, %xmm0
	movdqa	(%rdi), %xmm2
	movdqa	(%rsi), %xmm1
	pcmpeqb	%xmm1, %xmm0
	pslldq	$9, %xmm2		
	pcmpeqb	%xmm1, %xmm2
	psubb	%xmm0, %xmm2
	pmovmskb %xmm2, %r9d
	shr	%cl, %edx
	shr	%cl, %r9d
	sub	%r9d, %edx
	jnz	LABEL(less32bytes)
	movdqa	(%rdi), %xmm3

	UPDATE_STRNCMP_COUNTER

	pxor	%xmm0, %xmm0
	mov	$16, %rcx	/* index for loads */
	mov	$7, %r9d	/* rdi bytes already examined. Used in exit code */
	/*
	 * Setup %r10 value allows us to detect crossing a page boundary.
	 * When %r10 goes positive we are crossing a page boundary and
	 * need to do a nibble.
	 */
	lea	7(%rdi), %r10	 
	and	$0xfff, %r10	/* offset into 4K page */
	sub	$0x1000, %r10	/* subtract 4K pagesize */
	movdqa	%xmm3, %xmm4

	.p2align 4
LABEL(loop_ashr_7):
	add	$16, %r10
	jg	LABEL(nibble_ashr_7)	

LABEL(gobble_ashr_7):
	movdqa	(%rsi, %rcx), %xmm1
	movdqa	(%rdi, %rcx), %xmm2
	movdqa	%xmm2, %xmm4

	psrldq	$7, %xmm3		
	pslldq	$9, %xmm2		
	por	%xmm3, %xmm2

	pcmpeqb	%xmm1, %xmm0
	pcmpeqb	%xmm2, %xmm1
	psubb	%xmm0, %xmm1
	pmovmskb %xmm1, %edx
	sub	$0xffff, %edx
	jnz	LABEL(exit)

#ifdef USE_AS_STRNCMP
	sub	$16, %r11
	jbe	LABEL(strcmp_exitz)
#endif

	add	$16, %rcx
	movdqa	%xmm4, %xmm3

	add	$16, %r10
	jg	LABEL(nibble_ashr_7)	/* cross page boundary */

	movdqa	(%rsi, %rcx), %xmm1
	movdqa	(%rdi, %rcx), %xmm2
	movdqa	%xmm2, %xmm4

	psrldq	$7, %xmm3			
	pslldq 	$9, %xmm2		
	por	%xmm3, %xmm2

	pcmpeqb	%xmm1, %xmm0
	pcmpeqb	%xmm2, %xmm1
	psubb	%xmm0, %xmm1
	pmovmskb %xmm1, %edx
	sub	$0xffff, %edx
	jnz	LABEL(exit)

#ifdef USE_AS_STRNCMP
	sub	$16, %r11
	jbe	LABEL(strcmp_exitz)
#endif

	add	$16, %rcx
	movdqa	%xmm4, %xmm3
	jmp	LABEL(loop_ashr_7)		

	.p2align 4
LABEL(nibble_ashr_7):
	psrldq	$7, %xmm4		
	movdqa	(%rsi, %rcx), %xmm1
	pcmpeqb	%xmm1, %xmm0
	pcmpeqb	%xmm4, %xmm1
	psubb	%xmm0, %xmm1
	pmovmskb %xmm1, %edx
	sub	$0x01ff, %edx
	jnz	LABEL(exit)
#ifdef USE_AS_STRNCMP
	cmp	$9, %r11
	jbe	LABEL(strcmp_exitz)
#endif
 	pxor	%xmm0, %xmm0
	sub	$0x1000, %r10		/* subtract 4K from %r10 */
	jmp	LABEL(gobble_ashr_7)	

/*
 * ashr_8 handles the following cases: 
 * 	abs(str1 offset - str2 offset) = 8
 */
	.p2align 4
LABEL(ashr_8):
	pxor	%xmm0, %xmm0
	movdqa	(%rdi), %xmm2
	movdqa	(%rsi), %xmm1
	pcmpeqb	%xmm1, %xmm0
	pslldq	$8, %xmm2		
	pcmpeqb	%xmm1, %xmm2
	psubb	%xmm0, %xmm2
	pmovmskb %xmm2, %r9d
	shr	%cl, %edx
	shr	%cl, %r9d
	sub	%r9d, %edx
	jnz	LABEL(less32bytes)
	movdqa	(%rdi), %xmm3

	UPDATE_STRNCMP_COUNTER

	pxor	%xmm0, %xmm0
	mov	$16, %rcx	/* index for loads */
	mov	$8, %r9d	/* rdi bytes already examined. Used in exit code */
	/*
	 * Setup %r10 value allows us to detect crossing a page boundary.
	 * When %r10 goes positive we are crossing a page boundary and
	 * need to do a nibble.
	 */
	lea	8(%rdi), %r10	 
	and	$0xfff, %r10	/* offset into 4K page */
	sub	$0x1000, %r10	/* subtract 4K pagesize */
	movdqa	%xmm3, %xmm4

	.p2align 4
LABEL(loop_ashr_8):
	add	$16, %r10
	jg	LABEL(nibble_ashr_8)	

LABEL(gobble_ashr_8):
	movdqa	(%rsi, %rcx), %xmm1
	movdqa	(%rdi, %rcx), %xmm2
	movdqa	%xmm2, %xmm4

	psrldq	$8, %xmm3		
	pslldq	$8, %xmm2		
	por	%xmm3, %xmm2

	pcmpeqb	%xmm1, %xmm0
	pcmpeqb	%xmm2, %xmm1
	psubb	%xmm0, %xmm1
	pmovmskb %xmm1, %edx
	sub	$0xffff, %edx
	jnz	LABEL(exit)

#ifdef USE_AS_STRNCMP
	sub	$16, %r11
	jbe	LABEL(strcmp_exitz)
#endif

	add	$16, %rcx
	movdqa	%xmm4, %xmm3	

	add	$16, %r10
	jg	LABEL(nibble_ashr_8)	/* cross page boundary */

	movdqa	(%rsi, %rcx), %xmm1
	movdqa	(%rdi, %rcx), %xmm2
	movdqa	%xmm2, %xmm4

	psrldq	$8, %xmm3			
	pslldq 	$8, %xmm2		
	por	%xmm3, %xmm2

	pcmpeqb	%xmm1, %xmm0
	pcmpeqb	%xmm2, %xmm1
	psubb	%xmm0, %xmm1
	pmovmskb %xmm1, %edx
	sub	$0xffff, %edx
	jnz	LABEL(exit)

#ifdef USE_AS_STRNCMP
	sub	$16, %r11
	jbe	LABEL(strcmp_exitz)
#endif

	add	$16, %rcx
	movdqa	%xmm4, %xmm3
	jmp	LABEL(loop_ashr_8)		

	.p2align 4
LABEL(nibble_ashr_8):
	psrldq	$8, %xmm4		
	movdqa	(%rsi, %rcx), %xmm1
	pcmpeqb	%xmm1, %xmm0
	pcmpeqb	%xmm4, %xmm1
	psubb	%xmm0, %xmm1
	pmovmskb %xmm1, %edx
	sub	$0x00ff, %edx
	jnz	LABEL(exit)
#ifdef USE_AS_STRNCMP
	cmp	$8, %r11
	jbe	LABEL(strcmp_exitz)
#endif
 	pxor	%xmm0, %xmm0
	sub	$0x1000, %r10		/* subtract 4K from %r10 */
	jmp	LABEL(gobble_ashr_8)	

/*
 * ashr_9 handles the following cases: 
 * 	abs(str1 offset - str2 offset) = 7
 */
	.p2align 4
LABEL(ashr_9):
	pxor	%xmm0, %xmm0
	movdqa	(%rdi), %xmm2
	movdqa	(%rsi), %xmm1
	pcmpeqb	%xmm1, %xmm0
	pslldq	$7, %xmm2		
	pcmpeqb	%xmm1, %xmm2
	psubb	%xmm0, %xmm2
	pmovmskb %xmm2, %r9d
	shr	%cl, %edx
	shr	%cl, %r9d
	sub	%r9d, %edx
	jnz	LABEL(less32bytes)
	movdqa	(%rdi), %xmm3

	UPDATE_STRNCMP_COUNTER

	pxor	%xmm0, %xmm0
	mov	$16, %rcx	/* index for loads */
	mov	$9, %r9d	/* rdi bytes already examined. Used in exit code */
	/*
	 * Setup %r10 value allows us to detect crossing a page boundary.
	 * When %r10 goes positive we are crossing a page boundary and
	 * need to do a nibble.
	 */
	lea	9(%rdi), %r10	 
	and	$0xfff, %r10	/* offset into 4K page */
	sub	$0x1000, %r10	/* subtract 4K pagesize */
	movdqa	%xmm3, %xmm4

	.p2align 4
LABEL(loop_ashr_9):
	add	$16, %r10
	jg	LABEL(nibble_ashr_9)	

LABEL(gobble_ashr_9):
	movdqa	(%rsi, %rcx), %xmm1
	movdqa	(%rdi, %rcx), %xmm2
	movdqa	%xmm2, %xmm4

	psrldq	$9, %xmm3		
	pslldq	$7, %xmm2		
	por	%xmm3, %xmm2

	pcmpeqb	%xmm1, %xmm0
	pcmpeqb	%xmm2, %xmm1
	psubb	%xmm0, %xmm1
	pmovmskb %xmm1, %edx
	sub	$0xffff, %edx
	jnz	LABEL(exit)

#ifdef USE_AS_STRNCMP
	sub	$16, %r11
	jbe	LABEL(strcmp_exitz)
#endif

	add	$16, %rcx
	movdqa	%xmm4, %xmm3

	add	$16, %r10
	jg	LABEL(nibble_ashr_9)	/* cross page boundary */

	movdqa	(%rsi, %rcx), %xmm1
	movdqa	(%rdi, %rcx), %xmm2
	movdqa	%xmm2, %xmm4

	psrldq	$9, %xmm3			
	pslldq 	$7, %xmm2		
	por	%xmm3, %xmm2

	pcmpeqb	%xmm1, %xmm0
	pcmpeqb	%xmm2, %xmm1
	psubb	%xmm0, %xmm1
	pmovmskb %xmm1, %edx
	sub	$0xffff, %edx
	jnz	LABEL(exit)

#ifdef USE_AS_STRNCMP
	sub	$16, %r11
	jbe	LABEL(strcmp_exitz)
#endif

	add	$16, %rcx
	movdqa	%xmm4, %xmm3		/* store for next cycle */
	jmp	LABEL(loop_ashr_9)		

	.p2align 4
LABEL(nibble_ashr_9):
	psrldq	$9, %xmm4		
	movdqa	(%rsi, %rcx), %xmm1
	pcmpeqb	%xmm1, %xmm0
	pcmpeqb	%xmm4, %xmm1
	psubb	%xmm0, %xmm1
	pmovmskb %xmm1, %edx
	sub	$0x007f, %edx
	jnz	LABEL(exit)
#ifdef USE_AS_STRNCMP
	cmp	$7, %r11
	jbe	LABEL(strcmp_exitz)
#endif
 	pxor	%xmm0, %xmm0
	sub	$0x1000, %r10		/* subtract 4K from %r10 */
	jmp	LABEL(gobble_ashr_9)	

/*
 * ashr_10 handles the following cases: 
 * 	abs(str1 offset - str2 offset) = 6
 */
	.p2align 4
LABEL(ashr_10):
	pxor	%xmm0, %xmm0
	movdqa	(%rdi), %xmm2
	movdqa	(%rsi), %xmm1
	pcmpeqb	%xmm1, %xmm0
	pslldq	$6, %xmm2		
	pcmpeqb	%xmm1, %xmm2
	psubb	%xmm0, %xmm2
	pmovmskb %xmm2, %r9d
	shr	%cl, %edx
	shr	%cl, %r9d
	sub	%r9d, %edx
	jnz	LABEL(less32bytes)
	movdqa	(%rdi), %xmm3

	UPDATE_STRNCMP_COUNTER

	pxor	%xmm0, %xmm0
	mov	$16, %rcx	/* index for loads */
	mov	$10, %r9d	/* rdi bytes already examined. Used in exit code */
	/*
	 * Setup %r10 value allows us to detect crossing a page boundary.
	 * When %r10 goes positive we are crossing a page boundary and
	 * need to do a nibble.
	 */
	lea	10(%rdi), %r10	 
	and	$0xfff, %r10	/* offset into 4K page */
	sub	$0x1000, %r10	/* subtract 4K pagesize */
	movdqa	%xmm3, %xmm4

	.p2align 4
LABEL(loop_ashr_10):
	add	$16, %r10
	jg	LABEL(nibble_ashr_10)	

LABEL(gobble_ashr_10):
	movdqa	(%rsi, %rcx), %xmm1
	movdqa	(%rdi, %rcx), %xmm2
	movdqa	%xmm2, %xmm4

	psrldq	$10, %xmm3		
	pslldq	$6, %xmm2		
	por	%xmm3, %xmm2

	pcmpeqb	%xmm1, %xmm0
	pcmpeqb	%xmm2, %xmm1
	psubb	%xmm0, %xmm1
	pmovmskb %xmm1, %edx
	sub	$0xffff, %edx
	jnz	LABEL(exit)

#ifdef USE_AS_STRNCMP
	sub	$16, %r11
	jbe	LABEL(strcmp_exitz)
#endif

	add	$16, %rcx
	movdqa	%xmm4, %xmm3

	add	$16, %r10
	jg	LABEL(nibble_ashr_10)	/* cross page boundary */

	movdqa	(%rsi, %rcx), %xmm1
	movdqa	(%rdi, %rcx), %xmm2
	movdqa	%xmm2, %xmm4

	psrldq	$10, %xmm3			
	pslldq 	$6, %xmm2		
	por	%xmm3, %xmm2

	pcmpeqb	%xmm1, %xmm0
	pcmpeqb	%xmm2, %xmm1
	psubb	%xmm0, %xmm1
	pmovmskb %xmm1, %edx
	sub	$0xffff, %edx
	jnz	LABEL(exit)

#ifdef USE_AS_STRNCMP
	sub	$16, %r11
	jbe	LABEL(strcmp_exitz)
#endif

	add	$16, %rcx
	movdqa	%xmm4, %xmm3
	jmp	LABEL(loop_ashr_10)		

	.p2align 4
LABEL(nibble_ashr_10):
	psrldq	$10, %xmm4		
	movdqa	(%rsi, %rcx), %xmm1
	pcmpeqb	%xmm1, %xmm0
	pcmpeqb	%xmm4, %xmm1
	psubb	%xmm0, %xmm1
	pmovmskb %xmm1, %edx
	sub	$0x003f, %edx
	jnz	LABEL(exit)
#ifdef USE_AS_STRNCMP
	cmp	$6, %r11
	jbe	LABEL(strcmp_exitz)
#endif
 	pxor	%xmm0, %xmm0
	sub	$0x1000, %r10		/* subtract 4K from %r10 */
	jmp	LABEL(gobble_ashr_10)	

/*
 * ashr_11 handles the following cases: 
 * 	abs(str1 offset - str2 offset) = 5
 */
	.p2align 4
LABEL(ashr_11):
	pxor	%xmm0, %xmm0
	movdqa	(%rdi), %xmm2
	movdqa	(%rsi), %xmm1
	pcmpeqb	%xmm1, %xmm0
	pslldq	$5, %xmm2		
	pcmpeqb	%xmm1, %xmm2
	psubb	%xmm0, %xmm2
	pmovmskb %xmm2, %r9d
	shr	%cl, %edx
	shr	%cl, %r9d
	sub	%r9d, %edx
	jnz	LABEL(less32bytes)
	movdqa	(%rdi), %xmm3

	UPDATE_STRNCMP_COUNTER

	pxor	%xmm0, %xmm0
	mov	$16, %rcx	/* index for loads */
	mov	$11, %r9d	/* rdi bytes already examined. Used in exit code */
	/*
	 * Setup %r10 value allows us to detect crossing a page boundary.
	 * When %r10 goes positive we are crossing a page boundary and
	 * need to do a nibble.
	 */
	lea	11(%rdi), %r10	 
	and	$0xfff, %r10	/* offset into 4K page */
	sub	$0x1000, %r10	/* subtract 4K pagesize */
	movdqa	%xmm3, %xmm4

	.p2align 4
LABEL(loop_ashr_11):
	add	$16, %r10
	jg	LABEL(nibble_ashr_11)	

LABEL(gobble_ashr_11):
	movdqa	(%rsi, %rcx), %xmm1
	movdqa	(%rdi, %rcx), %xmm2
	movdqa	%xmm2, %xmm4

	psrldq	$11, %xmm3		
	pslldq	$5, %xmm2		
	por	%xmm3, %xmm2

	pcmpeqb	%xmm1, %xmm0
	pcmpeqb	%xmm2, %xmm1
	psubb	%xmm0, %xmm1
	pmovmskb %xmm1, %edx
	sub	$0xffff, %edx
	jnz	LABEL(exit)

#ifdef USE_AS_STRNCMP
	sub	$16, %r11
	jbe	LABEL(strcmp_exitz)
#endif

	add	$16, %rcx
	movdqa	%xmm4, %xmm3

	add	$16, %r10
	jg	LABEL(nibble_ashr_11)	/* cross page boundary */

	movdqa	(%rsi, %rcx), %xmm1
	movdqa	(%rdi, %rcx), %xmm2
	movdqa	%xmm2, %xmm4

	psrldq	$11, %xmm3			
	pslldq 	$5, %xmm2		
	por	%xmm3, %xmm2

	pcmpeqb	%xmm1, %xmm0
	pcmpeqb	%xmm2, %xmm1
	psubb	%xmm0, %xmm1
	pmovmskb %xmm1, %edx
	sub	$0xffff, %edx
	jnz	LABEL(exit)

#ifdef USE_AS_STRNCMP
	sub	$16, %r11
	jbe	LABEL(strcmp_exitz)
#endif

	add	$16, %rcx
	movdqa	%xmm4, %xmm3
	jmp	LABEL(loop_ashr_11)		

	.p2align 4
LABEL(nibble_ashr_11):
	psrldq	$11, %xmm4		
	movdqa	(%rsi, %rcx), %xmm1
	pcmpeqb	%xmm1, %xmm0
	pcmpeqb	%xmm4, %xmm1
	psubb	%xmm0, %xmm1
	pmovmskb %xmm1, %edx
	sub	$0x001f, %edx
	jnz	LABEL(exit)
#ifdef USE_AS_STRNCMP
	cmp	$5, %r11
	jbe	LABEL(strcmp_exitz)
#endif
 	pxor	%xmm0, %xmm0
	sub	$0x1000, %r10		/* subtract 4K from %r10 */
	jmp	LABEL(gobble_ashr_11)	

/*
 * ashr_12 handles the following cases: 
 * 	abs(str1 offset - str2 offset) = 4
 */
	.p2align 4
LABEL(ashr_12):
	pxor	%xmm0, %xmm0
	movdqa	(%rdi), %xmm2
	movdqa	(%rsi), %xmm1
	pcmpeqb	%xmm1, %xmm0
	pslldq	$4, %xmm2		
	pcmpeqb	%xmm1, %xmm2
	psubb	%xmm0, %xmm2
	pmovmskb %xmm2, %r9d
	shr	%cl, %edx
	shr	%cl, %r9d
	sub	%r9d, %edx
	jnz	LABEL(less32bytes)
	movdqa	(%rdi), %xmm3

	UPDATE_STRNCMP_COUNTER

	pxor	%xmm0, %xmm0
	mov	$16, %rcx	/* index for loads */
	mov	$12, %r9d	/* rdi bytes already examined. Used in exit code */
	/*
	 * Setup %r10 value allows us to detect crossing a page boundary.
	 * When %r10 goes positive we are crossing a page boundary and
	 * need to do a nibble.
	 */
	lea	12(%rdi), %r10	 
	and	$0xfff, %r10	/* offset into 4K page */
	sub	$0x1000, %r10	/* subtract 4K pagesize */
	movdqa	%xmm3, %xmm4

	.p2align 4
LABEL(loop_ashr_12):
	add	$16, %r10
	jg	LABEL(nibble_ashr_12)	

LABEL(gobble_ashr_12):
	movdqa	(%rsi, %rcx), %xmm1
	movdqa	(%rdi, %rcx), %xmm2
	movdqa	%xmm2, %xmm4

	psrldq	$12, %xmm3		
	pslldq	$4, %xmm2		
	por	%xmm3, %xmm2

	pcmpeqb	%xmm1, %xmm0	
	pcmpeqb	%xmm2, %xmm1
	psubb	%xmm0, %xmm1
	pmovmskb %xmm1, %edx
	sub	$0xffff, %edx
	jnz	LABEL(exit)

#ifdef USE_AS_STRNCMP
	sub	$16, %r11
	jbe	LABEL(strcmp_exitz)
#endif

	add	$16, %rcx
	movdqa	%xmm4, %xmm3

	add	$16, %r10
	jg	LABEL(nibble_ashr_12)	/* cross page boundary */

	movdqa	(%rsi, %rcx), %xmm1
	movdqa	(%rdi, %rcx), %xmm2
	movdqa	%xmm2, %xmm4

	psrldq	$12, %xmm3			
	pslldq 	$4, %xmm2		
	por	%xmm3, %xmm2

	pcmpeqb	%xmm1, %xmm0
	pcmpeqb	%xmm2, %xmm1
	psubb	%xmm0, %xmm1
	pmovmskb %xmm1, %edx
	sub	$0xffff, %edx
	jnz	LABEL(exit)

#ifdef USE_AS_STRNCMP
	sub	$16, %r11
	jbe	LABEL(strcmp_exitz)
#endif

	add	$16, %rcx
	movdqa	%xmm4, %xmm3
	jmp	LABEL(loop_ashr_12)		

	.p2align 4
LABEL(nibble_ashr_12):
	psrldq	$12, %xmm4		
	movdqa	(%rsi, %rcx), %xmm1
	pcmpeqb	%xmm1, %xmm0
	pcmpeqb	%xmm4, %xmm1
	psubb	%xmm0, %xmm1
	pmovmskb %xmm1, %edx
	sub	$0x000f, %edx
	jnz	LABEL(exit)
#ifdef USE_AS_STRNCMP
	cmp	$4, %r11
	jbe	LABEL(strcmp_exitz)
#endif
 	pxor	%xmm0, %xmm0
	sub	$0x1000, %r10		/* subtract 4K from %r10 */
	jmp	LABEL(gobble_ashr_12)	

/*
 * ashr_13 handles the following cases: 
 * 	abs(str1 offset - str2 offset) = 3
 */
	.p2align 4
LABEL(ashr_13):
	pxor	%xmm0, %xmm0
	movdqa	(%rdi), %xmm2
	movdqa	(%rsi), %xmm1
	pcmpeqb	%xmm1, %xmm0
	pslldq	$3, %xmm2		
	pcmpeqb	%xmm1, %xmm2
	psubb	%xmm0, %xmm2
	pmovmskb %xmm2, %r9d
	shr	%cl, %edx
	shr	%cl, %r9d
	sub	%r9d, %edx
	jnz	LABEL(less32bytes)
	movdqa	(%rdi), %xmm3

	UPDATE_STRNCMP_COUNTER

	pxor	%xmm0, %xmm0
	mov	$16, %rcx	/* index for loads */
	mov	$13, %r9d	/* rdi bytes already examined. Used in exit code */
	/*
	 * Setup %r10 value allows us to detect crossing a page boundary.
	 * When %r10 goes positive we are crossing a page boundary and
	 * need to do a nibble.
	 */
	lea	13(%rdi), %r10	 
	and	$0xfff, %r10	/* offset into 4K page */
	sub	$0x1000, %r10	/* subtract 4K pagesize */
	movdqa	%xmm3, %xmm4

	.p2align 4
LABEL(loop_ashr_13):
	add	$16, %r10
	jg	LABEL(nibble_ashr_13)	

LABEL(gobble_ashr_13):
	movdqa	(%rsi, %rcx), %xmm1
	movdqa	(%rdi, %rcx), %xmm2
	movdqa	%xmm2, %xmm4

	psrldq	$13, %xmm3		
	pslldq	$3, %xmm2		
	por	%xmm3, %xmm2

	pcmpeqb	%xmm1, %xmm0
	pcmpeqb	%xmm2, %xmm1
	psubb	%xmm0, %xmm1
	pmovmskb %xmm1, %edx
	sub	$0xffff, %edx
	jnz	LABEL(exit)

#ifdef USE_AS_STRNCMP
	sub	$16, %r11
	jbe	LABEL(strcmp_exitz)
#endif

	add	$16, %rcx
	movdqa	%xmm4, %xmm3

	add	$16, %r10
	jg	LABEL(nibble_ashr_13)	/* cross page boundary */

	movdqa	(%rsi, %rcx), %xmm1
	movdqa	(%rdi, %rcx), %xmm2
	movdqa	%xmm2, %xmm4

	psrldq	$13, %xmm3			
	pslldq 	$3, %xmm2		
	por	%xmm3, %xmm2

	pcmpeqb	%xmm1, %xmm0
	pcmpeqb	%xmm2, %xmm1
	psubb	%xmm0, %xmm1
	pmovmskb %xmm1, %edx
	sub	$0xffff, %edx
	jnz	LABEL(exit)

#ifdef USE_AS_STRNCMP
	sub	$16, %r11
	jbe	LABEL(strcmp_exitz)
#endif

	add	$16, %rcx
	movdqa	%xmm4, %xmm3
	jmp	LABEL(loop_ashr_13)		
	
	.p2align 4
LABEL(nibble_ashr_13):
	psrldq	$13, %xmm4		
	movdqa	(%rsi, %rcx), %xmm1
	pcmpeqb	%xmm1, %xmm0
	pcmpeqb	%xmm4, %xmm1
	psubb	%xmm0, %xmm1
	pmovmskb %xmm1, %edx
	sub	$0x0007, %edx
	jnz	LABEL(exit)
#ifdef USE_AS_STRNCMP
	cmp	$3, %r11
	jbe	LABEL(strcmp_exitz)
#endif
 	pxor	%xmm0, %xmm0
	sub	$0x1000, %r10		/* subtract 4K from %r10 */
	jmp	LABEL(gobble_ashr_13)	

/*
 * ashr_14 handles the following cases: 
 * 	abs(str1 offset - str2 offset) = 2
 */
	.p2align 4
LABEL(ashr_14):
	pxor	%xmm0, %xmm0
	movdqa	(%rdi), %xmm2
	movdqa	(%rsi), %xmm1
	pcmpeqb	%xmm1, %xmm0
	pslldq  $2, %xmm2		
	pcmpeqb	%xmm1, %xmm2
	psubb	%xmm0, %xmm2
	pmovmskb %xmm2, %r9d
	shr	%cl, %edx
	shr	%cl, %r9d
	sub	%r9d, %edx
	jnz	LABEL(less32bytes)
	movdqa	(%rdi), %xmm3

	UPDATE_STRNCMP_COUNTER

	pxor	%xmm0, %xmm0
	mov	$16, %rcx	/* index for loads */
	mov	$14, %r9d	/* rdi bytes already examined. Used in exit code */
	/*
	 * Setup %r10 value allows us to detect crossing a page boundary.
	 * When %r10 goes positive we are crossing a page boundary and
	 * need to do a nibble.
	 */
	lea	14(%rdi), %r10  
	and	$0xfff, %r10	/* offset into 4K page */
	sub	$0x1000, %r10	/* subtract 4K pagesize */
	movdqa	%xmm3, %xmm4

	.p2align 4
LABEL(loop_ashr_14):
	add	$16, %r10
	jg	LABEL(nibble_ashr_14)	

LABEL(gobble_ashr_14):
	movdqa	(%rsi, %rcx), %xmm1
	movdqa	(%rdi, %rcx), %xmm2
	movdqa	%xmm2, %xmm4

	psrldq	$14, %xmm3		
	pslldq	$2, %xmm2		
	por	%xmm3, %xmm2

	pcmpeqb	%xmm1, %xmm0
	pcmpeqb	%xmm2, %xmm1
	psubb	%xmm0, %xmm1
	pmovmskb %xmm1, %edx
	sub	$0xffff, %edx
	jnz	LABEL(exit)

#ifdef USE_AS_STRNCMP
	sub	$16, %r11
	jbe	LABEL(strcmp_exitz)
#endif

	add	$16, %rcx
	movdqa	%xmm4, %xmm3

	add	$16, %r10
	jg	LABEL(nibble_ashr_14)	/* cross page boundary */

	movdqa	(%rsi, %rcx), %xmm1
	movdqa	(%rdi, %rcx), %xmm2
	movdqa	%xmm2, %xmm4

	psrldq	$14, %xmm3			
	pslldq 	$2, %xmm2		
	por	%xmm3, %xmm2

	pcmpeqb	%xmm1, %xmm0
	pcmpeqb	%xmm2, %xmm1
	psubb	%xmm0, %xmm1
	pmovmskb %xmm1, %edx
	sub	$0xffff, %edx
	jnz	LABEL(exit)

#ifdef USE_AS_STRNCMP
	sub	$16, %r11
	jbe	LABEL(strcmp_exitz)
#endif

	add	$16, %rcx
	movdqa	%xmm4, %xmm3
	jmp	LABEL(loop_ashr_14)		

	.p2align 4
LABEL(nibble_ashr_14):
	psrldq	$14, %xmm4		
	movdqa	(%rsi, %rcx), %xmm1
	pcmpeqb	%xmm1, %xmm0
	pcmpeqb	%xmm4, %xmm1
	psubb	%xmm0, %xmm1
	pmovmskb %xmm1, %edx
	sub	$0x0003, %edx
	jnz	LABEL(exit)
#ifdef USE_AS_STRNCMP
	cmp	$2, %r11
	jbe	LABEL(strcmp_exitz)
#endif
 	pxor	%xmm0, %xmm0
	sub	$0x1000, %r10		/* subtract 4K from %r10 */
	jmp	LABEL(gobble_ashr_14)	

/*
 * ashr_15 handles the following cases: 
 * 	abs(str1 offset - str2 offset) = 1
 */
	.p2align 4
LABEL(ashr_15):
	pxor	%xmm0, %xmm0
	movdqa	(%rdi), %xmm2
	movdqa	(%rsi), %xmm1
	pcmpeqb	%xmm1, %xmm0
	pslldq	$1, %xmm2		
	pcmpeqb	%xmm1, %xmm2
	psubb	%xmm0, %xmm2
	pmovmskb %xmm2, %r9d
	shr	%cl, %edx
	shr	%cl, %r9d
	sub	%r9d, %edx
	jnz	LABEL(less32bytes)

	movdqa	(%rdi), %xmm3

	UPDATE_STRNCMP_COUNTER

	pxor	%xmm0, %xmm0
	mov	$16, %rcx	/* index for loads */
	mov	$15, %r9d	/* rdi bytes already examined. Used in exit code */
	/*
	 * Setup %r10 value allows us to detect crossing a page boundary.
	 * When %r10 goes positive we are crossing a page boundary and
	 * need to do a nibble.
	 */
	lea	15(%rdi), %r10	
	and	$0xfff, %r10	/* offset into 4K page */
	sub	$0x1000, %r10	/* subtract 4K pagesize */
	movdqa	%xmm3, %xmm4

	.p2align 4
LABEL(loop_ashr_15):
	add	$16, %r10
	jg	LABEL(nibble_ashr_15)

LABEL(gobble_ashr_15):
	movdqa	(%rsi, %rcx), %xmm1
	movdqa	(%rdi, %rcx), %xmm2
	movdqa	%xmm2, %xmm4

	psrldq	$15, %xmm3
	pslldq	$1, %xmm2
	por	%xmm3, %xmm2

	pcmpeqb	%xmm1, %xmm0
	pcmpeqb	%xmm2, %xmm1
	psubb	%xmm0, %xmm1
	pmovmskb %xmm1, %edx
	sub	$0xffff, %edx
	jnz	LABEL(exit)

#ifdef USE_AS_STRNCMP
	sub	$16, %r11
	jbe	LABEL(strcmp_exitz)
#endif

	add	$16, %rcx
	movdqa	%xmm4, %xmm3

	add	$16, %r10
	jg	LABEL(nibble_ashr_15)	/* cross page boundary */

	movdqa	(%rsi, %rcx), %xmm1
	movdqa	(%rdi, %rcx), %xmm2
	movdqa	%xmm2, %xmm4

	psrldq	$15, %xmm3
	pslldq 	$1, %xmm2
	por	%xmm3, %xmm2

	pcmpeqb	%xmm1, %xmm0
	pcmpeqb	%xmm2, %xmm1
	psubb	%xmm0, %xmm1
	pmovmskb %xmm1, %edx
	sub	$0xffff, %edx
	jnz	LABEL(exit)

#ifdef USE_AS_STRNCMP
	sub	$16, %r11
	jbe	LABEL(strcmp_exitz)
#endif

	add	$16, %rcx
	movdqa	%xmm4, %xmm3
	jmp	LABEL(loop_ashr_15)

	.p2align 4
LABEL(nibble_ashr_15):
	psrldq	$15, %xmm4		
	movdqa	(%rsi, %rcx), %xmm1
	pcmpeqb	%xmm1, %xmm0
	pcmpeqb	%xmm4, %xmm1
	psubb	%xmm0, %xmm1
	pmovmskb %xmm1, %edx
	sub	$0x0001, %edx
	jnz	LABEL(exit)
#ifdef USE_AS_STRNCMP
	cmp	$1, %r11
	jbe	LABEL(strcmp_exitz)
#endif
 	pxor	%xmm0, %xmm0
	sub	$0x1000, %r10		/* subtract 4K from %r10 */
	jmp	LABEL(gobble_ashr_15)	

	.p2align 4
LABEL(exit):
	lea	-16(%r9, %rcx), %rax	/* locate the exact offset for rdi */
LABEL(less32bytes):
	lea	(%rdi, %rax), %rdi	/* locate the exact address for first operand(rdi) */
	lea	(%rsi, %rcx), %rsi	/* locate the exact address for second operand(rsi) */
	test	%r8d, %r8d
	jz	LABEL(ret)
	xchg	%rsi, %rdi		/* recover original order according to flag(%r8d) */

	.p2align 4
LABEL(ret):
LABEL(less16bytes):
	/*
	 * Check to see if BSF is fast on this processor. If not, use a different
	 * exit tail.
	 */
	testl	$USE_BSF,.memops_method(%rip)
	jz	LABEL(AMD_exit)
	bsf	%rdx, %rdx		/* find and store bit index in %rdx */	

#ifdef USE_AS_STRNCMP
	sub	%rdx, %r11
	jbe	LABEL(strcmp_exitz)
#endif	
	xor	%ecx, %ecx		/* clear %ecx */
	xor	%eax, %eax		/* clear %eax */

	movb	(%rsi, %rdx), %cl
	movb	(%rdi, %rdx), %al

	sub	%ecx, %eax
	ret

#ifdef USE_AS_STRNCMP
LABEL(strcmp_exitz):
	xor	%eax, %eax
	ret
#endif

	/*
	 * This exit tail does not use the bsf instruction.
	 */
	.p2align 4
LABEL(AMD_exit):
	test	%dl, %dl
	jz	LABEL(next_8_bytes)

	test	$0x01, %dl
	jnz	LABEL(Byte0)

	test	$0x02, %dl
	jnz	LABEL(Byte1)

	test	$0x04, %dl
	jnz	LABEL(Byte2)

	test	$0x08, %dl
	jnz	LABEL(Byte3)

	test	$0x10, %dl
	jnz	LABEL(Byte4)

	test	$0x20, %dl
	jnz	LABEL(Byte5)

	test	$0x40, %dl
	jnz	LABEL(Byte6)

#ifdef USE_AS_STRNCMP
	sub	$7, %r11
	jbe	LABEL(strcmp_exitz)
#endif
	movzx	7(%rsi), %ecx
	movzx	7(%rdi), %eax

	sub	%ecx, %eax
	ret

	.p2align 4
LABEL(Byte0):
	/*
	 * never need to handle byte 0 for strncmpy
#ifdef USE_AS_STRNCMP
	sub	$0, %r11
	jbe	LABEL(strcmp_exitz)
#endif
	*/
	movzx	(%rsi), %ecx
	movzx	(%rdi), %eax

	sub	%ecx, %eax
	ret

	.p2align 4
LABEL(Byte1):

#ifdef USE_AS_STRNCMP
	sub	$1, %r11
	jbe	LABEL(strcmp_exitz)
#endif
	movzx	1(%rsi), %ecx
	movzx	1(%rdi), %eax

	sub	%ecx, %eax
	ret

	.p2align 4
LABEL(Byte2):

#ifdef USE_AS_STRNCMP
	sub	$2, %r11
	jbe	LABEL(strcmp_exitz)
#endif
	movzx	2(%rsi), %ecx
	movzx	2(%rdi), %eax

	sub	%ecx, %eax
	ret

	.p2align 4
LABEL(Byte3):

#ifdef USE_AS_STRNCMP
	sub	$3, %r11
	jbe	LABEL(strcmp_exitz)
#endif
	movzx	3(%rsi), %ecx
	movzx	3(%rdi), %eax

	sub	%ecx, %eax
	ret

	.p2align 4
LABEL(Byte4):

#ifdef USE_AS_STRNCMP
	sub	$4, %r11
	jbe	LABEL(strcmp_exitz)
#endif
	movzx	4(%rsi), %ecx
	movzx	4(%rdi), %eax

	sub	%ecx, %eax
	ret

	.p2align 4
LABEL(Byte5):

#ifdef USE_AS_STRNCMP
	sub	$5, %r11
	jbe	LABEL(strcmp_exitz)
#endif
	movzx	5(%rsi), %ecx
	movzx	5(%rdi), %eax

	sub	%ecx, %eax
	ret

	.p2align 4
LABEL(Byte6):

#ifdef USE_AS_STRNCMP
	sub	$6, %r11
	jbe	LABEL(strcmp_exitz)
#endif
	movzx	6(%rsi), %ecx
	movzx	6(%rdi), %eax

	sub	%ecx, %eax
	ret

	.p2align 4
LABEL(next_8_bytes):
	add	$8, %rdi
	add	$8, %rsi
#ifdef USE_AS_STRNCMP
	sub	$8, %r11
	jbe	LABEL(strcmp_exitz)
#endif
	test	$0x01, %dh
	jnz	LABEL(Byte0)

	test	$0x02, %dh
	jnz	LABEL(Byte1)

	test	$0x04, %dh
	jnz	LABEL(Byte2)

	test	$0x08, %dh
	jnz	LABEL(Byte3)

	test	$0x10, %dh
	jnz	LABEL(Byte4)

	test	$0x20, %dh
	jnz	LABEL(Byte5)

	test	$0x40, %dh
	jnz	LABEL(Byte6)

#ifdef USE_AS_STRNCMP
	sub	$7, %r11
	jbe	LABEL(strcmp_exitz)
#endif
	movzx	7(%rsi), %ecx
	movzx	7(%rdi), %eax

	sub	%ecx, %eax
	ret

	.pushsection .rodata
	.p2align 4
LABEL(unaligned_table):
	.int	LABEL(ashr_0) - LABEL(unaligned_table)
	.int	LABEL(ashr_15) - LABEL(unaligned_table)
	.int	LABEL(ashr_14) - LABEL(unaligned_table)
	.int	LABEL(ashr_13) - LABEL(unaligned_table)
	.int	LABEL(ashr_12) - LABEL(unaligned_table)
	.int	LABEL(ashr_11) - LABEL(unaligned_table)
	.int	LABEL(ashr_10) - LABEL(unaligned_table)
	.int	LABEL(ashr_9) - LABEL(unaligned_table)
	.int	LABEL(ashr_8) - LABEL(unaligned_table)
	.int	LABEL(ashr_7) - LABEL(unaligned_table)
	.int	LABEL(ashr_6) - LABEL(unaligned_table)
	.int	LABEL(ashr_5) - LABEL(unaligned_table)
	.int	LABEL(ashr_4) - LABEL(unaligned_table)
	.int	LABEL(ashr_3) - LABEL(unaligned_table)
	.int	LABEL(ashr_2) - LABEL(unaligned_table)
	.int	LABEL(ashr_1) - LABEL(unaligned_table)
	.popsection
#ifdef USE_AS_STRNCMP
	SET_SIZE(strncmp)
#else
	SET_SIZE(strcmp)		/* (const char *, const char *) */
#endif
