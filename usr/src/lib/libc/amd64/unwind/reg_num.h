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

/*
 * DWARF register numbers for AMD64
 */

#ifndef _REG_NUM_H
#define	_REG_NUM_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Dwarf register numbers for AMD64
 * Only those with trailing comments are actually tracked
 */
#define	GPR_RAX	0
#define	GPR_RDX	1
#define	GPR_RCX	2
#define	GPR_RBX	3	/* callee saves */
#define	GPR_RSI	4
#define	GPR_RDI	5
#define	FP_RBP	6	/* callee saves (optional frame pointer) */
#define	SP_RSP	7	/* stack pointer */
#define	EIR_R8	8
#define	EIR_R9	9
#define	EIR_R10	10
#define	EIR_R11	11
#define	EIR_R12	12	/* callee saves */
#define	EIR_R13	13	/* callee saves */
#define	EIR_R14	14	/* callee saves */
#define	EIR_R15	15	/* callee saves */
#define	RET_ADD	16	/* virtual register - really caller's PC */
#define	CF_ADDR	17	/* virtual register - tracks frame location */

#if 0
#define	SSE_XMM0	17
#define	SSE_XMM1	18
#define	SSE_XMM2	19
#define	SSE_XMM3	20
#define	SSE_XMM4	21
#define	SSE_XMM5	22
#define	SSE_XMM6	23
#define	SSE_XMM7	24
#define	SSE_XMM8	25
#define	SSE_XMM9	26
#define	SSE_XMM10	27
#define	SSE_XMM11	28
#define	SSE_XMM12	29
#define	SSE_XMM13	30
#define	SSE_XMM14	31
#define	SSE_XMM15	32
#define	FP_ST0		33
#define	FP_ST1		34
#define	FP_ST2		35
#define	FP_ST3		36
#define	FP_ST4		37
#define	FP_ST5		38
#define	FP_ST6		39
#define	FP_ST7		40
#define	MMX_MMN0	41
#define	MMX_MMN1	42
#define	MMX_MMN2	43
#define	MMX_MMN3	44
#define	MMX_MMN4	45
#define	MMX_MMN5	46
#define	MMX_MMN6	47
#define	MMX_MMN7	48
#endif
#define	BAD_REG		49

/*
 * register arrays used in support routines contain 16 8-byte slots
 * indexed from GPR_RAX to EIR_R15
 *
 *	%rax	0	0	<undefined>
 *	%rdx	1	8	handler parameter
 *	%rcx	2	16	handler parameter
 *	%rbx	3	24	preserved
 *	%rsi	4	32	handler parameter
 *	%rdi	5	40	handler parameter
 *	%rbp	6	48	frame pointer
 *	%rsp	7	56	stack pointer
 *	%r8	8	64	<undefined>
 *	%r9	9	72	<undefined>
 *	%r10	10	80	<undefined>
 *	%r11	11	88	<undefined>
 *	%r12	12	96	preserved
 *	%r13	13	104	preserved
 *	%r14	14	112	preserved
 *	%r15	15	120	preserved
 *
 * register state arrays used to hold propagation information
 * have two additional elements (indices RET_ADD and CF_ADDR)
 */

#endif	/* _REG_NUM_H */
