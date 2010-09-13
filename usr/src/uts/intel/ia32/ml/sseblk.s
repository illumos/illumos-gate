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

#pragma	ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/asm_linkage.h>
#include <sys/regset.h>
#include <sys/privregs.h>

#if defined(__lint)
#include <sys/types.h>
#include <sys/archsystm.h>
#else
#include "assym.h"
#endif

/*
 * Do block operations using Streaming SIMD extensions
 */

#if defined(DEBUG)
#if defined(__amd64)
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
#elif defined(__i386)
#define	ASSERT_KPREEMPT_DISABLED(t, r32, msg)	\
	movl	%gs:CPU_THREAD, t;		\
	movsbl	T_PREEMPT(t), r32;		\
	testl	r32, r32;			\
	jne	5f;				\
	pushl	%ebp;				\
	movl	%esp, %ebp;			\
	pushl	$msg;				\
	call	panic;				\
5:
#endif	/* __i386 */
#else	/* DEBUG */
#define	ASSERT_KPREEMPT_DISABLED(t, r32, msg)
#endif	/* DEBUG */

#define	BLOCKSHIFT	6
#define	BLOCKSIZE	64	/* (1 << BLOCKSHIFT) */
#define	BLOCKMASK	63	/* (BLOCKSIZE - 1) */

#if (1 << BLOCKSHIFT) != BLOCKSIZE || BLOCKMASK != (BLOCKSIZE - 1)
#error	"mucked up constants"
#endif

#if defined(__lint)

/*ARGSUSED*/
void
hwblkclr(void *addr, size_t size)
{}

#else	/* __lint */

#if defined(__amd64)
#define	ADD	addq
#define	SUB	subq
#else
#define	ADD	addl
#define	SUB	subl
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
	ADD	$BLOCKSIZE, dst;		\
	SUB	$1, cnt

#define	ZERO_LOOP_FINI_XMM(dst)			\
	mfence

#define	RSTOR_XMM0(r)				\
	movdqa	0x0(r), %xmm0;			\
	RSTOR_XMM_EPILOG(r, 1)

#if defined(__amd64)

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

#elif defined(__i386)

	/*
	 * %eax		dst
	 * %ecx		size in bytes, loop count
	 * %ebx		saved %cr0 (#if DEBUG then t->t_preempt)
	 * %edi		pointer to %xmm register save area
	 */
	ENTRY(hwblkclr)
	movl	4(%esp), %eax
	movl	8(%esp), %ecx
	testl	$BLOCKMASK, %eax	/* address must be BLOCKSIZE aligned */
	jne	.dobzero
	cmpl	$BLOCKSIZE, %ecx	/* size must be at least BLOCKSIZE */
	jl	.dobzero
	testl	$BLOCKMASK, %ecx 	/* .. and be a multiple of BLOCKSIZE */
	jne	.dobzero
	shrl	$BLOCKSHIFT, %ecx
	movl	0xc(%esp), %edx
	pushl	%ebx

	pushl	%esi
	ASSERT_KPREEMPT_DISABLED(%esi, %ebx, .not_disabled)
	popl	%esi
	movl	%cr0, %ebx
	clts
	testl	$CR0_TS, %ebx
	jnz	1f

	pushl	%edi
	SAVE_XMM0(%edi)
1:	ZERO_LOOP_INIT_XMM(%eax)
9:	ZERO_LOOP_BODY_XMM(%eax, %ecx)
	jnz	9b
	ZERO_LOOP_FINI_XMM(%eax)

	testl	$CR0_TS, %ebx
	jnz	2f
	RSTOR_XMM0(%edi)
	popl	%edi
2:	movl	%ebx, %cr0
	popl	%ebx
	ret
.dobzero:
	jmp	bzero
	SET_SIZE(hwblkclr)

#endif	/* __i386 */
#endif	/* __lint */


#if defined(__lint)

/*ARGSUSED*/
void
hwblkpagecopy(const void *src, void *dst)
{}

#else	/* __lint */

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
	ADD	$0x80, src

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
	ADD	$0x80, dst;			\
	movdqa	0x60(src), %xmm6;		\
	movdqa	0x70(src), %xmm7;		\
	ADD	$0x80, src;			\
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

#if defined(__amd64)

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

#elif defined(__i386)

	/*
	 * %eax		src
	 * %edx		dst
	 * %ecx		loop count
	 * %ebx		saved %cr0 (#if DEBUG then t->t_prempt)
	 * %edi		pointer to %xmm register save area
	 * %esi		#if DEBUG temporary thread pointer
	 */
	ENTRY(hwblkpagecopy)
	movl	4(%esp), %eax
	movl	8(%esp), %edx
	PREFETCH_START(%eax)
	pushl	%ebx
	/*
	 * PAGESIZE is 4096, each loop moves 128 bytes, but the initial
	 * load and final store save us one loop count
	 */
	movl	$_CONST(32 - 1), %ecx
	pushl	%esi
	ASSERT_KPREEMPT_DISABLED(%esi, %ebx, .not_disabled)
	popl	%esi
	movl	%cr0, %ebx
	clts
	testl	$CR0_TS, %ebx
	jnz	3f
	pushl	%edi
	SAVE_XMMS(%edi)
3:	COPY_LOOP_INIT_XMM(%eax)
4:	COPY_LOOP_BODY_XMM(%eax, %edx, %ecx)
	jnz	4b
	COPY_LOOP_FINI_XMM(%edx)
	testl	$CR0_TS, %ebx
	jnz	5f
	RSTOR_XMMS(%edi)
	popl	%edi
5:	movl	%ebx, %cr0
	popl	%ebx
	mfence
	ret
	SET_SIZE(hwblkpagecopy)

#endif	/* __i386 */
#endif	/* __lint */

#if defined(__lint)

/*
 * Version of hwblkclr which doesn't use XMM registers.
 * Note that it requires aligned dst and len.
 *
 * XXPV This needs to be performance tuned at some point.
 *	Is 4 the best number of iterations to unroll?
 */
/*ARGSUSED*/
void
block_zero_no_xmm(void *dst, int len)
{}

#else	/* __lint */

#if defined(__amd64)

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

#elif defined(__i386)

	ENTRY(block_zero_no_xmm)
	pushl	%ebp
	movl	%esp, %ebp
	xorl	%eax, %eax
	movl	8(%ebp), %edx
	movl	12(%ebp), %ecx
	addl	%ecx, %edx
	negl	%ecx
1:
	movnti	%eax, (%edx, %ecx)
	movnti	%eax, 4(%edx, %ecx)
	movnti	%eax, 8(%edx, %ecx)
	movnti	%eax, 12(%edx, %ecx)
	addl	$16, %ecx
	jnz	1b
	mfence
	leave
	ret
	SET_SIZE(block_zero_no_xmm)

#endif	/* __i386 */
#endif	/* __lint */


#if defined(__lint)

/*
 * Version of page copy which doesn't use XMM registers.
 *
 * XXPV	This needs to be performance tuned at some point.
 *	Is 4 the right number of iterations to unroll?
 *	Is the load/store order optimal? Should it use prefetch?
 */
/*ARGSUSED*/
void
page_copy_no_xmm(void *dst, void *src)
{}

#else	/* __lint */

#if defined(__amd64)

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

#elif defined(__i386)

	ENTRY(page_copy_no_xmm)
	pushl	%esi
	movl	$MMU_STD_PAGESIZE, %ecx
	movl	8(%esp), %edx
	movl	12(%esp), %esi
	addl	%ecx, %edx
	addl	%ecx, %esi
	negl	%ecx
1:
	movl	(%esi, %ecx), %eax
	movnti	%eax, (%edx, %ecx)
	movl	4(%esi, %ecx), %eax
	movnti	%eax, 4(%edx, %ecx)
	movl	8(%esi, %ecx), %eax
	movnti	%eax, 8(%edx, %ecx)
	movl	12(%esi, %ecx), %eax
	movnti	%eax, 12(%edx, %ecx)
	addl	$16, %ecx
	jnz	1b
	mfence
	popl	%esi
	ret
	SET_SIZE(page_copy_no_xmm)

#endif	/* __i386 */
#endif	/* __lint */

#if defined(DEBUG) && !defined(__lint)
	.text
.not_disabled:
	.string	"sseblk: preemption not disabled!"
#endif
