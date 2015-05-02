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
 * Copyright 2015 Nexenta Systems, Inc.  All rights reserved.
 *
 * Copyright (c) 1989, 2010, Oracle and/or its affiliates. All rights reserved.
 */
/*	Copyright (c) 1990, 1991 UNIX System Laboratories, Inc. */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T		*/
/*	All Rights Reserved	*/

#ifndef	_SYS_REGSET_H
#define	_SYS_REGSET_H

#include <sys/feature_tests.h>

#if !defined(_ASM)
#include <sys/types.h>
#endif
#include <sys/mcontext.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * The names and offsets defined here should be specified by the
 * AMD64 ABI suppl.
 *
 * We make fsbase and gsbase part of the lwp context (since they're
 * the only way to access the full 64-bit address range via the segment
 * registers) and thus belong here too.  However we treat them as
 * read-only; if %fs or %gs are updated, the results of the descriptor
 * table lookup that those updates implicitly cause will be reflected
 * in the corresponding fsbase and/or gsbase values the next time the
 * context can be inspected.  However it is NOT possible to override
 * the fsbase/gsbase settings via this interface.
 *
 * Direct modification of the base registers (thus overriding the
 * descriptor table base address) can be achieved with _lwp_setprivate.
 */

#define	REG_GSBASE	27
#define	REG_FSBASE	26
#define	REG_DS		25
#define	REG_ES		24

#define	REG_GS		23
#define	REG_FS		22
#define	REG_SS		21
#define	REG_RSP		20
#define	REG_RFL		19
#define	REG_CS		18
#define	REG_RIP		17
#define	REG_ERR		16
#define	REG_TRAPNO	15
#define	REG_RAX		14
#define	REG_RCX		13
#define	REG_RDX		12
#define	REG_RBX		11
#define	REG_RBP		10
#define	REG_RSI		9
#define	REG_RDI		8
#define	REG_R8		7
#define	REG_R9		6
#define	REG_R10		5
#define	REG_R11		4
#define	REG_R12		3
#define	REG_R13		2
#define	REG_R14		1
#define	REG_R15		0

/*
 * The names and offsets defined here are specified by i386 ABI suppl.
 */

#define	SS		18	/* only stored on a privilege transition */
#define	UESP		17	/* only stored on a privilege transition */
#define	EFL		16
#define	CS		15
#define	EIP		14
#define	ERR		13
#define	TRAPNO		12
#define	EAX		11
#define	ECX		10
#define	EDX		9
#define	EBX		8
#define	ESP		7
#define	EBP		6
#define	ESI		5
#define	EDI		4
#define	DS		3
#define	ES		2
#define	FS		1
#define	GS		0

/* aliases for portability */

#if defined(__amd64)

#define	REG_PC	REG_RIP
#define	REG_FP	REG_RBP
#define	REG_SP	REG_RSP
#define	REG_PS	REG_RFL
#define	REG_R0	REG_RAX
#define	REG_R1	REG_RDX

#else	/* __i386 */

#define	REG_PC	EIP
#define	REG_FP	EBP
#define	REG_SP	UESP
#define	REG_PS	EFL
#define	REG_R0	EAX
#define	REG_R1	EDX

#endif	/* __i386 */

#define	NGREG	_NGREG

#if !defined(_ASM)

#ifdef	__i386
/*
 * (This structure definition is specified in the i386 ABI supplement)
 * It's likely we can just get rid of the struct __old_fpu or maybe
 * move it to $SRC/uts/intel/ia32/os/fpu.c which appears to be the
 * only place that uses it.  See: www.illumos.org/issues/6284
 */
typedef struct __old_fpu {
	union {
		struct __old_fpchip_state	/* fp extension state */
		{
			int 	state[27];	/* 287/387 saved state */
			int 	status;		/* status word saved at */
						/* exception */
		} fpchip_state;
		struct __old_fp_emul_space	/* for emulator(s) */
		{
			char	fp_emul[246];
			char	fp_epad[2];
		} fp_emul_space;
		int 	f_fpregs[62];		/* union of the above */
	} fp_reg_set;
	long    	f_wregs[33];		/* saved weitek state */
} __old_fpregset_t;
#endif	/* __i386 */

#if defined(__amd64)
#define	_NDEBUGREG	16
#else
#define	_NDEBUGREG	8
#endif

typedef struct dbregset {
	unsigned long	debugreg[_NDEBUGREG];
} dbregset_t;

#endif	/* _ASM */

/*
 * The version of privregs.h that is used on implementations that run on
 * processors that support the AMD64 instruction set is deliberately not
 * imported here.
 *
 * The amd64 'struct regs' definition may -not- compatible with either
 * 32-bit or 64-bit core file contents, nor with the ucontext.  As a result,
 * the 'regs' structure cannot be used portably by applications, and should
 * only be used by the kernel implementation.
 *
 * The inclusion of the i386 version of privregs.h allows for some limited
 * source compatibility with 32-bit applications who expect to use
 * 'struct regs' to match the context of a 32-bit core file, or a ucontext_t.
 *
 * Note that the ucontext_t actually describes the general register in terms
 * of the gregset_t data type, as described in this file.  Note also
 * that the core file content is defined by core(4) in terms of data types
 * defined by procfs -- see proc(4).
 */
#if defined(__i386) && \
	(!defined(_KERNEL) && !defined(_XPG4_2) || defined(__EXTENSIONS__))
#include <sys/privregs.h>
#endif	/* __i386 (!_KERNEL && !_XPG4_2 || __EXTENSIONS__) */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_REGSET_H */
