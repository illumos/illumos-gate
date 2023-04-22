/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2023 Oxide Computer Company
 */

	.file	"xsave_asm64.s"

/*
 * Test utility routines that we need assembler for. 64-bit addition.
 */

#include <sys/asm_linkage.h>
#include "xsave_util.h"

#define	GET_FPU_XMM(src, i)	\
	leaq	(i * XSU_ZMM_U32 * 4)(src), %rax; \
	movdqu	%xmm##i, (%rax)

#define	GET_FPU_YMM(src, i)	\
	leaq	(i * XSU_ZMM_U32 * 4)(src), %rax; \
	vmovdqu	%ymm##i, (%rax)

#define	GET_FPU_ZMM(src, i)	\
	leaq	(i * XSU_ZMM_U32 * 4)(src), %rax; \
	vmovdqu64	%zmm##i, (%rax)

#define	GET_MASK(src, i)	\
	leaq	(0x800 + i * 8)(src), %rax; \
	kmovq	%k##i, (%rax)

	/*
	 * void xsu_getfpu(xsu_fpu_t *data, uint32_t type)
	 *
	 * Our job is to get the entire contents of the FPU and save it into our
	 * data structure.
	 */
	ENTRY(xsu_getfpu)
	cmpl	$XSU_XMM, %esi
	je	get_xmm
	cmpl	$XSU_YMM, %esi
	je	get_ymm
	cmpl	$XSU_ZMM, %esi
	je	get_zmm
	call	abort
get_xmm:
	GET_FPU_XMM(%rdi, 0)
	GET_FPU_XMM(%rdi, 1)
	GET_FPU_XMM(%rdi, 2)
	GET_FPU_XMM(%rdi, 3)
	GET_FPU_XMM(%rdi, 4)
	GET_FPU_XMM(%rdi, 5)
	GET_FPU_XMM(%rdi, 6)
	GET_FPU_XMM(%rdi, 7)
	GET_FPU_XMM(%rdi, 8)
	GET_FPU_XMM(%rdi, 9)
	GET_FPU_XMM(%rdi, 10)
	GET_FPU_XMM(%rdi, 11)
	GET_FPU_XMM(%rdi, 12)
	GET_FPU_XMM(%rdi, 13)
	GET_FPU_XMM(%rdi, 14)
	GET_FPU_XMM(%rdi, 15)
	jmp	get_done
get_ymm:
	GET_FPU_YMM(%rdi, 0)
	GET_FPU_YMM(%rdi, 1)
	GET_FPU_YMM(%rdi, 2)
	GET_FPU_YMM(%rdi, 3)
	GET_FPU_YMM(%rdi, 4)
	GET_FPU_YMM(%rdi, 5)
	GET_FPU_YMM(%rdi, 6)
	GET_FPU_YMM(%rdi, 7)
	GET_FPU_YMM(%rdi, 8)
	GET_FPU_YMM(%rdi, 9)
	GET_FPU_YMM(%rdi, 10)
	GET_FPU_YMM(%rdi, 11)
	GET_FPU_YMM(%rdi, 12)
	GET_FPU_YMM(%rdi, 13)
	GET_FPU_YMM(%rdi, 14)
	GET_FPU_YMM(%rdi, 15)
	jmp	get_done
get_zmm:
	GET_FPU_ZMM(%rdi, 0)
	GET_FPU_ZMM(%rdi, 1)
	GET_FPU_ZMM(%rdi, 2)
	GET_FPU_ZMM(%rdi, 3)
	GET_FPU_ZMM(%rdi, 4)
	GET_FPU_ZMM(%rdi, 5)
	GET_FPU_ZMM(%rdi, 6)
	GET_FPU_ZMM(%rdi, 7)
	GET_FPU_ZMM(%rdi, 8)
	GET_FPU_ZMM(%rdi, 9)
	GET_FPU_ZMM(%rdi, 10)
	GET_FPU_ZMM(%rdi, 11)
	GET_FPU_ZMM(%rdi, 12)
	GET_FPU_ZMM(%rdi, 13)
	GET_FPU_ZMM(%rdi, 14)
	GET_FPU_ZMM(%rdi, 15)
	GET_FPU_ZMM(%rdi, 16)
	GET_FPU_ZMM(%rdi, 17)
	GET_FPU_ZMM(%rdi, 18)
	GET_FPU_ZMM(%rdi, 19)
	GET_FPU_ZMM(%rdi, 20)
	GET_FPU_ZMM(%rdi, 21)
	GET_FPU_ZMM(%rdi, 22)
	GET_FPU_ZMM(%rdi, 23)
	GET_FPU_ZMM(%rdi, 24)
	GET_FPU_ZMM(%rdi, 25)
	GET_FPU_ZMM(%rdi, 25)
	GET_FPU_ZMM(%rdi, 26)
	GET_FPU_ZMM(%rdi, 27)
	GET_FPU_ZMM(%rdi, 28)
	GET_FPU_ZMM(%rdi, 29)
	GET_FPU_ZMM(%rdi, 30)
	GET_FPU_ZMM(%rdi, 31)
	GET_MASK(%rdi, 0)
	GET_MASK(%rdi, 1)
	GET_MASK(%rdi, 2)
	GET_MASK(%rdi, 3)
	GET_MASK(%rdi, 4)
	GET_MASK(%rdi, 5)
	GET_MASK(%rdi, 6)
	GET_MASK(%rdi, 7)
get_done:
	ret
	SET_SIZE(xsu_getfpu)

#define	SET_FPU_XMM(src, i)	\
	leaq	(i * XSU_ZMM_U32 * 4)(src), %rax; \
	movdqu	(%rax), %xmm##i

#define	SET_FPU_YMM(src, i)	\
	leaq	(i * XSU_ZMM_U32 * 4)(src), %rax; \
	vmovdqu	(%rax), %ymm##i

#define	SET_FPU_ZMM(src, i)	\
	leaq	(i * XSU_ZMM_U32 * 4)(src), %rax; \
	vmovdqu64	(%rax), %zmm##i

#define	SET_MASK(src, i)	\
	leaq	(0x800 + i * 8)(src), %rax; \
	kmovq	(%rax), %k##i

	/*
	 * void xsu_setfpu(const xsu_fpu_t *data, uint32_t type)
	 *
	 * Our job is to override the contents of the FPU with this structure
	 * that we've been given. The type indicates how much of it to use.
	 */
	ENTRY(xsu_setfpu)
	cmpl	$XSU_XMM, %esi
	je	set_xmm
	cmpl	$XSU_YMM, %esi
	je	set_ymm
	cmpl	$XSU_ZMM, %esi
	je	set_zmm
	call	abort
set_xmm:
	SET_FPU_XMM(%rdi, 0)
	SET_FPU_XMM(%rdi, 1)
	SET_FPU_XMM(%rdi, 2)
	SET_FPU_XMM(%rdi, 3)
	SET_FPU_XMM(%rdi, 4)
	SET_FPU_XMM(%rdi, 5)
	SET_FPU_XMM(%rdi, 6)
	SET_FPU_XMM(%rdi, 7)
	SET_FPU_XMM(%rdi, 8)
	SET_FPU_XMM(%rdi, 9)
	SET_FPU_XMM(%rdi, 10)
	SET_FPU_XMM(%rdi, 11)
	SET_FPU_XMM(%rdi, 12)
	SET_FPU_XMM(%rdi, 13)
	SET_FPU_XMM(%rdi, 14)
	SET_FPU_XMM(%rdi, 15)
	jmp	set_done
set_ymm:
	SET_FPU_YMM(%rdi, 0)
	SET_FPU_YMM(%rdi, 1)
	SET_FPU_YMM(%rdi, 2)
	SET_FPU_YMM(%rdi, 3)
	SET_FPU_YMM(%rdi, 4)
	SET_FPU_YMM(%rdi, 5)
	SET_FPU_YMM(%rdi, 6)
	SET_FPU_YMM(%rdi, 7)
	SET_FPU_YMM(%rdi, 8)
	SET_FPU_YMM(%rdi, 9)
	SET_FPU_YMM(%rdi, 10)
	SET_FPU_YMM(%rdi, 11)
	SET_FPU_YMM(%rdi, 12)
	SET_FPU_YMM(%rdi, 13)
	SET_FPU_YMM(%rdi, 14)
	SET_FPU_YMM(%rdi, 15)
	jmp	set_done
set_zmm:
	SET_FPU_ZMM(%rdi, 0)
	SET_FPU_ZMM(%rdi, 1)
	SET_FPU_ZMM(%rdi, 2)
	SET_FPU_ZMM(%rdi, 3)
	SET_FPU_ZMM(%rdi, 4)
	SET_FPU_ZMM(%rdi, 5)
	SET_FPU_ZMM(%rdi, 6)
	SET_FPU_ZMM(%rdi, 7)
	SET_FPU_ZMM(%rdi, 8)
	SET_FPU_ZMM(%rdi, 9)
	SET_FPU_ZMM(%rdi, 10)
	SET_FPU_ZMM(%rdi, 11)
	SET_FPU_ZMM(%rdi, 12)
	SET_FPU_ZMM(%rdi, 13)
	SET_FPU_ZMM(%rdi, 14)
	SET_FPU_ZMM(%rdi, 15)
	SET_FPU_ZMM(%rdi, 16)
	SET_FPU_ZMM(%rdi, 17)
	SET_FPU_ZMM(%rdi, 18)
	SET_FPU_ZMM(%rdi, 19)
	SET_FPU_ZMM(%rdi, 20)
	SET_FPU_ZMM(%rdi, 21)
	SET_FPU_ZMM(%rdi, 22)
	SET_FPU_ZMM(%rdi, 23)
	SET_FPU_ZMM(%rdi, 24)
	SET_FPU_ZMM(%rdi, 25)
	SET_FPU_ZMM(%rdi, 25)
	SET_FPU_ZMM(%rdi, 26)
	SET_FPU_ZMM(%rdi, 27)
	SET_FPU_ZMM(%rdi, 28)
	SET_FPU_ZMM(%rdi, 29)
	SET_FPU_ZMM(%rdi, 30)
	SET_FPU_ZMM(%rdi, 31)
	SET_MASK(%rdi, 0)
	SET_MASK(%rdi, 1)
	SET_MASK(%rdi, 2)
	SET_MASK(%rdi, 3)
	SET_MASK(%rdi, 4)
	SET_MASK(%rdi, 5)
	SET_MASK(%rdi, 6)
	SET_MASK(%rdi, 7)
set_done:
	ret
	SET_SIZE(xsu_setfpu)
