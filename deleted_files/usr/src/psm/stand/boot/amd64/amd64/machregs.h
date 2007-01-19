/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_AMD64_MACHREGS_H
#define	_AMD64_MACHREGS_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#if !defined(_ASM)

/*
 * AMD64 is somewhat unique in that it involves switching the state
 * of the machine back and forth between being a complete implementation
 * of an i386 processor, and a complete implementation of an amd64
 * processor.  As a result, it has to "know" about the state of both
 * physical machines.
 */

#include <sys/types.h>
#include <amd64/tss.h>
#include <amd64/segments.h>

struct i386_machregs {

	/*
	 * This is the privileged machine (register) state
	 */

	uint32_t	r_cr0;
	uint32_t	r_cr2;
	uint32_t	r_cr3;
	uint32_t	r_cr4;

	union {
		desctbr_t	un_gdt;
		uint64_t	__pad0;
	}		r_gdt_un;
#define	r_gdt	r_gdt_un.un_gdt

	union {
		desctbr_t	un_idt;
		uint64_t	__pad0;
	}		r_idt_un;
#define	r_idt	r_idt_un.un_idt

	uint32_t	r_ldt;
	uint32_t	r_tr;

	/*
	 * The rest of this structure is an i386 'struct regs'
	 */

	int32_t		r_gs;
	int32_t		r_fs;
	int32_t		r_es;
	int32_t		r_ds;
	int32_t		r_edi;
	int32_t		r_esi;
	int32_t		r_ebp;
	int32_t		r_esp;
	int32_t		r_ebx;
	int32_t		r_edx;
	int32_t		r_ecx;
	int32_t		r_eax;
	int32_t		r_trapno;
	int32_t		r_err;
	int32_t		r_eip;
	int32_t		r_cs;
	int32_t		r_efl;
	int32_t		r_uesp;
	int32_t		r_ss;
};

/*
 * XX64 need assertions to validate structure offsets are really
 * what they need to be!
 */

struct amd64_machregs {
	/*
	 * This is the privileged machine (register) state
	 * (Does NOT include amd64-specific MSRs, because boot doesn't
	 * touch them)
	 *
	 * XX64	An open question, however, is if the switch between amd64
	 * and i386 modes damages any of them -- we may need to save more
	 * than present below.
	 */

	uint64_t	r_kgsbase;
	uint64_t	r_gsbase;
	uint64_t	r_fsbase;

	uint64_t	r_cr0;
	uint64_t	r_cr2;
	uint64_t	r_cr3;
	uint64_t	r_cr4;
	uint64_t	r_cr8;

	union {
		desctbr64_t	un_gdt;
		upad128_t	__pad0;
	}		r_gdt_un;

	union {
		desctbr64_t	un_idt;
		upad128_t	__pad0;
	}		r_idt_un;

	uint64_t	r_ldt;
	uint64_t	r_tr;

	/*
	 * The rest of this structure is an amd64 'struct regs'
	 *
	 * It is intended to match the 'struct regs' definition
	 * in amd64/sys/privregs.h
	 *
	 * XX64 Need to ensure that it does!
	 */

	int64_t		r_rdi;
	int64_t		r_rsi;
	int64_t		r_rdx;
	int64_t		r_rcx;
	int64_t		r_r8;
	int64_t		r_r9;
	int64_t		r_rax;
	int64_t		r_rbx;
	int64_t		r_rbp;
	int64_t		r_r10;
	int64_t		r_r11;
	int64_t		r_r12;
	int64_t		r_r13;
	int64_t		r_r14;
	int64_t		r_r15;
	int64_t		r_gs;
	int64_t		r_fs;
	int64_t		r_ds;
	int64_t		r_es;
	int64_t		r_trapno;
	int64_t		r_err;
	int64_t		r_rip;
	int64_t		r_cs;
	int64_t		r_rfl;
	int64_t		r_rsp;
	int64_t		r_ss;
};

/*
 * C-calling convention argument order:
 *
 *	%rdi, %rsi, %rdx, %rcx, %r8, %r9
 *
 * and how to get them out of an amd64_machregs structure:
 */

#define	_ARG1(rp)	((rp)->r_rdi)
#define	_ARG2(rp)	((rp)->r_rsi)
#define	_ARG3(rp)	((rp)->r_rdx)
#define	_ARG4(rp)	((rp)->r_rcx)
#define	_ARG5(rp)	((rp)->r_r8)
#define	_ARG6(rp)	((rp)->r_r9)

#endif	/* !_ASM */

#ifdef	__cplusplus
}
#endif

#endif	/* _AMD64_MACHREGS_H */
