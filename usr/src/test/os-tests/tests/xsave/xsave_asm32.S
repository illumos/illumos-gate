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

	.file	"xsave_asm32.s"

/*
 * Test utility routines that we need assembler for. 32-bit addition.
 */

#include <sys/asm_linkage.h>
#include "xsave_util.h"

#define	GET_FPU_XMM(src, i)	\
	leal	(i * XSU_ZMM_U32 * 4)(src), %eax; \
	movdqu	%xmm##i, (%eax)

#define	GET_FPU_YMM(src, i)	\
	leal	(i * XSU_ZMM_U32 * 4)(src), %eax; \
	vmovdqu	%ymm##i, (%eax)

#define	GET_FPU_ZMM(src, i)	\
	leal	(i * XSU_ZMM_U32 * 4)(src), %eax; \
	vmovdqu64	%zmm##i, (%eax)

#define	GET_MASK(src, i)	\
	leal	(0x800 + i * 8)(src), %eax; \
	kmovq	%k##i, (%eax)

	/*
	 * void xsu_getfpu(xsu_fpu_t *data, uint32_t type)
	 *
	 * Our job is to get the entire contents of the FPU and save it into our
	 * data structure.
	 */
	ENTRY(xsu_getfpu)
	movl	8(%esp), %eax
	movl	4(%esp), %edx
	cmpl	$XSU_XMM, %eax
	je	get_xmm
	cmpl	$XSU_YMM, %eax
	je	get_ymm
	cmpl	$XSU_ZMM, %eax
	je	get_zmm
	call	abort
get_xmm:
	GET_FPU_XMM(%edx, 0)
	GET_FPU_XMM(%edx, 1)
	GET_FPU_XMM(%edx, 2)
	GET_FPU_XMM(%edx, 3)
	GET_FPU_XMM(%edx, 4)
	GET_FPU_XMM(%edx, 5)
	GET_FPU_XMM(%edx, 6)
	GET_FPU_XMM(%edx, 7)
	jmp	get_done
get_ymm:
	GET_FPU_YMM(%edx, 0)
	GET_FPU_YMM(%edx, 1)
	GET_FPU_YMM(%edx, 2)
	GET_FPU_YMM(%edx, 3)
	GET_FPU_YMM(%edx, 4)
	GET_FPU_YMM(%edx, 5)
	GET_FPU_YMM(%edx, 6)
	GET_FPU_YMM(%edx, 7)
	jmp	get_done
get_zmm:
	GET_FPU_ZMM(%edx, 0)
	GET_FPU_ZMM(%edx, 1)
	GET_FPU_ZMM(%edx, 2)
	GET_FPU_ZMM(%edx, 3)
	GET_FPU_ZMM(%edx, 4)
	GET_FPU_ZMM(%edx, 5)
	GET_FPU_ZMM(%edx, 6)
	GET_FPU_ZMM(%edx, 7)
	GET_MASK(%edx, 0)
	GET_MASK(%edx, 1)
	GET_MASK(%edx, 2)
	GET_MASK(%edx, 3)
	GET_MASK(%edx, 4)
	GET_MASK(%edx, 5)
	GET_MASK(%edx, 6)
	GET_MASK(%edx, 7)
get_done:
	ret
	SET_SIZE(xsu_getfpu)

#define	SET_FPU_XMM(src, i)	\
	leal	(i * XSU_ZMM_U32 * 4)(src), %eax; \
	movdqu	(%eax), %xmm##i

#define	SET_FPU_YMM(src, i)	\
	leal	(i * XSU_ZMM_U32 * 4)(src), %eax; \
	vmovdqu	(%eax), %ymm##i

#define	SET_FPU_ZMM(src, i)	\
	leal	(i * XSU_ZMM_U32 * 4)(src), %eax; \
	vmovdqu64	(%eax), %zmm##i

#define	SET_MASK(src, i)	\
	leal	(0x800 + i * 8)(src), %eax; \
	kmovq	(%eax), %k##i

	/*
	 * void xsu_setfpu(const xsu_fpu_t *data, uint32_t type)
	 *
	 * Our job is to override the contents of the FPU with this structure
	 * that we've been given. The type indicates how much of it to use.
	 */
	ENTRY(xsu_setfpu)
	movl	8(%esp), %eax
	movl	4(%esp), %edx
	cmpl	$XSU_XMM, %eax
	je	set_xmm
	cmpl	$XSU_YMM, %eax
	je	set_ymm
	cmpl	$XSU_ZMM, %eax
	je	set_zmm
	call	abort
set_xmm:
	SET_FPU_XMM(%edx, 0)
	SET_FPU_XMM(%edx, 1)
	SET_FPU_XMM(%edx, 2)
	SET_FPU_XMM(%edx, 3)
	SET_FPU_XMM(%edx, 4)
	SET_FPU_XMM(%edx, 5)
	SET_FPU_XMM(%edx, 6)
	SET_FPU_XMM(%edx, 7)
	jmp	set_done
set_ymm:
	SET_FPU_YMM(%edx, 0)
	SET_FPU_YMM(%edx, 1)
	SET_FPU_YMM(%edx, 2)
	SET_FPU_YMM(%edx, 3)
	SET_FPU_YMM(%edx, 4)
	SET_FPU_YMM(%edx, 5)
	SET_FPU_YMM(%edx, 6)
	SET_FPU_YMM(%edx, 7)
	jmp	set_done
set_zmm:
	SET_FPU_ZMM(%edx, 0)
	SET_FPU_ZMM(%edx, 1)
	SET_FPU_ZMM(%edx, 2)
	SET_FPU_ZMM(%edx, 3)
	SET_FPU_ZMM(%edx, 4)
	SET_FPU_ZMM(%edx, 5)
	SET_FPU_ZMM(%edx, 6)
	SET_FPU_ZMM(%edx, 7)
	SET_MASK(%edx, 0)
	SET_MASK(%edx, 1)
	SET_MASK(%edx, 2)
	SET_MASK(%edx, 3)
	SET_MASK(%edx, 4)
	SET_MASK(%edx, 5)
	SET_MASK(%edx, 6)
	SET_MASK(%edx, 7)
set_done:
	ret
	SET_SIZE(xsu_setfpu)
