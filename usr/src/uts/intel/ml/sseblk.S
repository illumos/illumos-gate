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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright 2019 Joyent, Inc.
 */

#include <sys/asm_linkage.h>
#include <sys/regset.h>
#include <sys/privregs.h>

#include "assym.h"

/*
 * Do block operations using Streaming SIMD extensions
 */

#if defined(DEBUG)
#define	ASSERT_KPREEMPT_DISABLED(t, r32, msg)	\
	movq	%gs:CPU_THREAD, t;		\
	movsbl	T_PREEMPT(t), r32;		\
	testl	r32, r32;			\
	jne	5f;				\
	pushq	%rbp;				\
	movq	%rsp, %rbp;			\
	leaq	msg(%rip), %rdi;		\
	xorl	%eax, %eax;			\
	call	panic;				\
5:
#else	/* DEBUG */
#define	ASSERT_KPREEMPT_DISABLED(t, r32, msg)
#endif	/* DEBUG */

#define	BLOCKSHIFT	6
#define	BLOCKSIZE	64	/* (1 << BLOCKSHIFT) */
#define	BLOCKMASK	63	/* (BLOCKSIZE - 1) */

#if (1 << BLOCKSHIFT) != BLOCKSIZE || BLOCKMASK != (BLOCKSIZE - 1)
#error	"mucked up constants"
#endif

#define	SAVE_XMM0(r)				\
	SAVE_XMM_PROLOG(r, 1);			\
	movdqa	%xmm0, (r)

#define	ZERO_LOOP_INIT_XMM(dst)			\
	pxor	%xmm0, %xmm0

#define	ZERO_LOOP_BODY_XMM(dst, cnt)		\
	movntdq	%xmm0, (dst);			\
	movntdq	%xmm0, 0x10(dst);		\
	movntdq	%xmm0, 0x20(dst);		\
	movntdq	%xmm0, 0x30(dst);		\
	addq	$BLOCKSIZE, dst;		\
	subq	$1, cnt

#define	ZERO_LOOP_FINI_XMM(dst)			\
	mfence

#define	RSTOR_XMM0(r)				\
	movdqa	0x0(r), %xmm0;			\
	RSTOR_XMM_EPILOG(r, 1)

	/*
	 * %rdi		dst
	 * %rsi		size
	 * %rax		saved %cr0 (#if DEBUG then %eax is t->t_preempt)
	 * %r8		pointer to %xmm register save area
	 */
	ENTRY(hwblkclr)
	pushq	%rbp
	movq	%rsp, %rbp
	testl	$BLOCKMASK, %edi	/* address must be BLOCKSIZE aligned */
	jne	.dobzero
	cmpq	$BLOCKSIZE, %rsi	/* size must be at least BLOCKSIZE */
	jl	.dobzero
	testq	$BLOCKMASK, %rsi	/* .. and be a multiple of BLOCKSIZE */
	jne	.dobzero
	shrq	$BLOCKSHIFT, %rsi

	ASSERT_KPREEMPT_DISABLED(%r11, %eax, .not_disabled)
	movq	%cr0, %rax
	clts
	testl	$CR0_TS, %eax
	jnz	1f

	SAVE_XMM0(%r8)
1:	ZERO_LOOP_INIT_XMM(%rdi)
9:	ZERO_LOOP_BODY_XMM(%rdi, %rsi)
	jnz	9b
	ZERO_LOOP_FINI_XMM(%rdi)

	testl	$CR0_TS, %eax
	jnz	2f
	RSTOR_XMM0(%r8)
2:	movq	%rax, %cr0
	leave
	ret
.dobzero:
	leave
	jmp	bzero
	SET_SIZE(hwblkclr)


#define	PREFETCH_START(src)			\
	prefetchnta	0x0(src);		\
	prefetchnta	0x40(src)

#define	SAVE_XMMS(r)				\
	SAVE_XMM_PROLOG(r, 8);			\
	movdqa	%xmm0, (r);			\
	movdqa	%xmm1, 0x10(r);			\
	movdqa	%xmm2, 0x20(r);			\
	movdqa	%xmm3, 0x30(r);			\
	movdqa	%xmm4, 0x40(r);			\
	movdqa	%xmm5, 0x50(r);			\
	movdqa	%xmm6, 0x60(r);			\
	movdqa	%xmm7, 0x70(r)

#define	COPY_LOOP_INIT_XMM(src)			\
	prefetchnta	0x80(src);		\
	prefetchnta	0xc0(src);		\
	movdqa	0x0(src), %xmm0;		\
	movdqa	0x10(src), %xmm1;		\
	movdqa	0x20(src), %xmm2;		\
	movdqa	0x30(src), %xmm3;		\
	movdqa	0x40(src), %xmm4;		\
	movdqa	0x50(src), %xmm5;		\
	movdqa	0x60(src), %xmm6;		\
	movdqa	0x70(src), %xmm7;		\
	addq	$0x80, src

#define	COPY_LOOP_BODY_XMM(src, dst, cnt)	\
	prefetchnta	0x80(src);		\
	prefetchnta	0xc0(src);		\
	prefetchnta	0x100(src);		\
	prefetchnta	0x140(src);		\
	movntdq	%xmm0, (dst);			\
	movntdq	%xmm1, 0x10(dst);		\
	movntdq	%xmm2, 0x20(dst);		\
	movntdq	%xmm3, 0x30(dst);		\
	movdqa	0x0(src), %xmm0;		\
	movdqa	0x10(src), %xmm1;		\
	movntdq	%xmm4, 0x40(dst);		\
	movntdq	%xmm5, 0x50(dst);		\
	movdqa	0x20(src), %xmm2;		\
	movdqa	0x30(src), %xmm3;		\
	movntdq	%xmm6, 0x60(dst);		\
	movntdq	%xmm7, 0x70(dst);		\
	movdqa	0x40(src), %xmm4;		\
	movdqa	0x50(src), %xmm5;		\
	addq	$0x80, dst;			\
	movdqa	0x60(src), %xmm6;		\
	movdqa	0x70(src), %xmm7;		\
	addq	$0x80, src;			\
	subl	$1, cnt

#define	COPY_LOOP_FINI_XMM(dst)			\
	movntdq	%xmm0, 0x0(dst);		\
	movntdq	%xmm1, 0x10(dst);		\
	movntdq	%xmm2, 0x20(dst);		\
	movntdq	%xmm3, 0x30(dst);		\
	movntdq	%xmm4, 0x40(dst);		\
	movntdq	%xmm5, 0x50(dst);		\
	movntdq %xmm6, 0x60(dst);		\
	movntdq	%xmm7, 0x70(dst)

#define	RSTOR_XMMS(r)				\
	movdqa	0x0(r), %xmm0;			\
	movdqa	0x10(r), %xmm1;			\
	movdqa	0x20(r), %xmm2;			\
	movdqa	0x30(r), %xmm3;			\
	movdqa	0x40(r), %xmm4;			\
	movdqa	0x50(r), %xmm5;			\
	movdqa	0x60(r), %xmm6;			\
	movdqa	0x70(r), %xmm7;			\
	RSTOR_XMM_EPILOG(r, 8)

	/*
	 * %rdi		src
	 * %rsi		dst
	 * %rdx		#if DEBUG then curthread
	 * %ecx		loop count
	 * %rax		saved %cr0 (#if DEBUG then %eax is t->t_prempt)
	 * %r8		pointer to %xmm register save area
	 */
	ENTRY(hwblkpagecopy)
	pushq	%rbp
	movq	%rsp, %rbp
	PREFETCH_START(%rdi)
	/*
	 * PAGESIZE is 4096, each loop moves 128 bytes, but the initial
	 * load and final store save us on loop count
	 */
	movl	$_CONST(32 - 1), %ecx
	ASSERT_KPREEMPT_DISABLED(%rdx, %eax, .not_disabled)
	movq	%cr0, %rax
	clts
	testl	$CR0_TS, %eax
	jnz	3f
	SAVE_XMMS(%r8)
3:	COPY_LOOP_INIT_XMM(%rdi)
4:	COPY_LOOP_BODY_XMM(%rdi, %rsi, %ecx)
	jnz	4b
	COPY_LOOP_FINI_XMM(%rsi)
	testl	$CR0_TS, %eax
	jnz	5f
	RSTOR_XMMS(%r8)
5:	movq	%rax, %cr0
	mfence
	leave
	ret
	SET_SIZE(hwblkpagecopy)

	ENTRY(block_zero_no_xmm)
	pushq	%rbp
	movq	%rsp, %rbp
	xorl	%eax, %eax
	addq	%rsi, %rdi
	negq	%rsi
1:
	movnti	%rax, (%rdi, %rsi)
	movnti	%rax, 8(%rdi, %rsi)
	movnti	%rax, 16(%rdi, %rsi)
	movnti	%rax, 24(%rdi, %rsi)
	addq	$32, %rsi
	jnz	1b
	mfence
	leave
	ret
	SET_SIZE(block_zero_no_xmm)


	ENTRY(page_copy_no_xmm)
	movq	$MMU_STD_PAGESIZE, %rcx
	addq	%rcx, %rdi
	addq	%rcx, %rsi
	negq	%rcx
1:
	movq	(%rsi, %rcx), %rax
	movnti	%rax, (%rdi, %rcx)
	movq	8(%rsi, %rcx), %rax
	movnti	%rax, 8(%rdi, %rcx)
	movq	16(%rsi, %rcx), %rax
	movnti	%rax, 16(%rdi, %rcx)
	movq	24(%rsi, %rcx), %rax
	movnti	%rax, 24(%rdi, %rcx)
	addq	$32, %rcx
	jnz	1b
	mfence
	ret
	SET_SIZE(page_copy_no_xmm)

#if defined(DEBUG)
	.text
.not_disabled:
	.string	"sseblk: preemption not disabled!"
#endif
