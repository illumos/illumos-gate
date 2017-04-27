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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright 2017 Joyent, Inc.
 */

#ifndef _SYS_ASM_MISC_H
#define	_SYS_ASM_MISC_H

#ifdef	__cplusplus
extern "C" {
#endif

#ifdef _ASM	/* The remainder of this file is only for assembly files */

/* Load reg with pointer to per-CPU structure */
#if defined(__amd64)
#define	LOADCPU(reg)			\
	movq	%gs:CPU_SELF, reg;
#else
#define	LOADCPU(reg)			\
	movl	%gs:CPU_SELF, reg;
#endif

#define	RET_INSTR	0xc3
#define	NOP_INSTR	0x90
#define	STI_INSTR	0xfb
#define	JMP_INSTR	0x00eb


#if defined(__i386)

#define	_HOT_PATCH_PROLOG			\
	push	%ebp;				\
	mov	%esp, %ebp;			\
	push	%ebx;				\
	push	%esi;				\
	push	%edi

#define	_HOT_PATCH(srcaddr, dstaddr, size)	\
	movl	$srcaddr, %esi;			\
	movl	$dstaddr, %edi;			\
	movl	$size, %ebx;			\
0:	pushl	$1;				\
	/*CSTYLED*/				\
	movzbl	(%esi), %eax;			\
	pushl	%eax;				\
	pushl	%edi;				\
	call	hot_patch_kernel_text;		\
	addl	$12, %esp;			\
	inc	%edi;				\
	inc	%esi;				\
	dec	%ebx;				\
	test	%ebx, %ebx;			\
	jne	0b

#define	_HOT_PATCH_EPILOG			\
	pop	%edi;				\
	pop	%esi;				\
	pop	%ebx;				\
	mov	%ebp, %esp;			\
	pop	%ebp

#endif	/* __i386 */

#endif /* _ASM */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_ASM_MISC_H */
