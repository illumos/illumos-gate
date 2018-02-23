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
 * Copyright (c) 1992, 2010, Oracle and/or its affiliates. All rights reserved.
 */
/*
 * Copyright (c) 2010, Intel Corporation.
 * All rights reserved.
 */
/*
 * Copyright 2018 Joyent, Inc.
 */

#ifndef	_SYS_RM_PLATTER_H
#define	_SYS_RM_PLATTER_H

#include <sys/types.h>
#include <sys/tss.h>
#include <sys/segments.h>

#ifdef	__cplusplus
extern "C" {
#endif

#define	RM_PLATTER_CODE_SIZE		0x400
#define	RM_PLATTER_CPU_HALT_CODE_SIZE	0x100

typedef	struct rm_platter {
	char		rm_code[RM_PLATTER_CODE_SIZE];
	char		rm_cpu_halt_code[RM_PLATTER_CPU_HALT_CODE_SIZE];
#if defined(__amd64)
	/*
	 * The compiler will want to 64-bit align the 64-bit rm_gdt_base
	 * pointer, so we need to add an extra four bytes of padding here to
	 * make sure rm_gdt_lim and rm_gdt_base will align to create a proper
	 * ten byte GDT pseudo-descriptor.
	 */
	uint32_t	rm_gdt_pad;
#endif	/* __amd64 */
	ushort_t	rm_debug;
	ushort_t	rm_gdt_lim;	/* stuff for lgdt */
	user_desc_t	*rm_gdt_base;
#if defined(__amd64)
	/*
	 * The compiler will want to 64-bit align the 64-bit rm_idt_base
	 * pointer, so we need to add an extra four bytes of padding here to
	 * make sure rm_idt_lim and rm_idt_base will align to create a proper
	 * ten byte IDT pseudo-descriptor.
	 */
	uint32_t	rm_idt_pad;
#endif	/* __amd64 */
	ushort_t	rm_cpu_halted;	/* non-zero if CPU has been halted */
	ushort_t	rm_idt_lim;	/* stuff for lidt */
	gate_desc_t	*rm_idt_base;
	uint_t		rm_pdbr;	/* cr3 value */
	uint_t		rm_cpu;		/* easy way to know which CPU we are */
	uint_t		rm_filler3;
	uint_t		rm_cr4;		/* cr4 value on cpu0 */
#if defined(__amd64)
	/*
	 * Temporary GDT for the brief transition from real mode to protected
	 * mode before a CPU continues on into long mode.
	 *
	 * Putting it here assures it will be located in identity mapped memory
	 * (va == pa, 1:1).
	 *
	 * rm_temp_gdt is sized to hold only a null descriptor in slot zero
	 * and a 64-bit code descriptor in slot one.
	 *
	 * rm_temp_[gi]dt_lim and rm_temp_[gi]dt_base are the pseudo-descriptors
	 * for the temporary GDT and IDT, respectively.
	 */
	uint64_t	rm_temp_gdt[2];
	ushort_t	rm_temp_gdtdesc_pad;	/* filler to align GDT desc */
	ushort_t	rm_temp_gdt_lim;
	uint32_t	rm_temp_gdt_base;
	ushort_t	rm_temp_idtdesc_pad;	/* filler to align IDT desc */
	ushort_t	rm_temp_idt_lim;
	uint32_t	rm_temp_idt_base;

	/*
	 * The code executing in the rm_platter needs the offset into the
	 * platter at which the 64-bit code starts, so have mp_startup
	 * calculate it and store it here.
	 */
	uint32_t	rm_longmode64_addr;
#endif	/* __amd64 */
} rm_platter_t;

/*
 * cpu tables put within a single structure two of the tables which need to be
 * allocated when a CPU starts up.
 *
 * Note: the tss should be 16 byte aligned for best performance on amd64
 * Since DEFAULTSTKSIZE is a multiple of PAGESIZE tss will be aligned.
 */
struct cpu_tables {
	/* IST stacks */
	char		ct_stack1[DEFAULTSTKSZ];	/* dblfault */
#if !defined(__xpv)
	char		ct_stack2[DEFAULTSTKSZ];	/* nmi */
	char		ct_stack3[DEFAULTSTKSZ];	/* mce */
#endif
	tss_t		ct_tss;
};

/*
 * gdt entries are 8 bytes long, ensure that we have an even no. of them.
 */
#if ((NGDT / 2) * 2 != NGDT)
#error "rm_platter.h: tss not properly aligned"
#endif

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_RM_PLATTER_H */
