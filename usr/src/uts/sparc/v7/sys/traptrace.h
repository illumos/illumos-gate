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
 * Copyright (c) 1990-2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef _SYS_TRAPTRACE_H
#define	_SYS_TRAPTRACE_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Trap tracing. If TRAPTRACE is defined, every trap records info
 * in a circular buffer.  Define TRAPTRACE in Makefile.sun4m.
 *
 * Trap trace records are 8 words, consisting of the %tbr, %psr, %pc, %sp,
 * %g7 (THREAD_REG), and up to three other words.
 *
 * Auxilliary entries (not of just a trap), have obvious non-%tbr values in
 * the first word.
 */
#define	TRAP_ENT_TBR	0x00
#define	TRAP_ENT_PSR	0x04
#define	TRAP_ENT_PC	0x08
#define	TRAP_ENT_SP	0x0c
#define	TRAP_ENT_G7	0x10
#define	TRAP_ENT_TR	0x14
#define	TRAP_ENT_F1	0x18
#define	TRAP_ENT_F2	0x1c

#define	TRAP_ENT_SIZE	32
#define	TRAP_TSIZE	(TRAP_ENT_SIZE*256)

/*
 * Trap tracing buffer header.
 */

/*
 * Example buffer header in locore.s:
 *
 * trap_trace_ctl:
 * 	.word	trap_tr0		! next	CPU 0
 * 	.word	trap_tr0		! first
 * 	.word	trap_tr0 + TRAP_TSIZE	! limit
 * 	.word	0			! junk for alignment of prom dump
 *
 * 	.word	trap_tr1		! next	CPU 1
 * 	.word	trap_tr1		! first
 * 	.word	trap_tr1 + TRAP_TSIZE	! limit
 * 	.word	0			! junk for alignment of prom dump
 *
 * 	.word	trap_tr2		! next	CPU 2
 * 	.word	trap_tr2		! first
 * 	.word	trap_tr2 + TRAP_TSIZE	! limit
 * 	.word	0			! junk for alignment of prom dump
 *
 * 	.word	trap_tr3		! next	CPU 3
 * 	.word	trap_tr3		! first
 * 	.word	trap_tr3 + TRAP_TSIZE	! limit
 * 	.word	0			! junk for alignment of prom dump
 * 	.align	16
 *
 * Offsets of words in trap_trace_ctl:
 */
#define	TRAPTR_NEXT	0		/* next trace entry pointer */
#define	TRAPTR_FIRST	4		/* start of buffer */
#define	TRAPTR_LIMIT	8		/* pointer past end of buffer */

#define	TRAPTR_SIZE_SHIFT	4	/* shift count for CPU indexing */

#ifdef	_ASM

/*
 * TRACE_PTR(ptr, scr1) - get trap trace entry pointer.
 *	ptr is the register to receive the trace pointer.
 *	reg is a different register to be used as scratch.
 */
#define	TRACE_PTR(ptr, scr1)			\
	CPU_INDEX(scr1);			\
	sll	scr1, TRAPTR_SIZE_SHIFT, scr1;	\
	set	trap_trace_ctl, ptr; 		\
	ld	[ptr + scr1], ptr;		\
	set	panicstr, scr1;			\
	ld	[scr1], scr1;			\
	tst	scr1;				\
	bz	.+0xc;				\
	sethi	%hi(trap_tr_panic), scr1;	\
	or	scr1, %lo(trap_tr_panic), ptr

/*
 * TRACE_NEXT(ptr, scr1, scr2) - advance the trap trace pointer.
 *	ptr is the register holding the current trace pointer (from TRACE_PTR).
 *	scr1, and scr2 are scratch registers (different from ptr).
 */
#define	TRACE_NEXT(ptr, scr1, scr2)		\
	CPU_INDEX(scr2);			\
	sll	scr2, TRAPTR_SIZE_SHIFT, scr2;	\
	set	trap_trace_ctl, scr1;		\
	add	scr2, scr1, scr1;		\
	add	ptr, TRAP_ENT_SIZE, ptr;	\
	ld	[scr1 + TRAPTR_LIMIT], scr2;	\
	cmp	ptr, scr2;			\
	/* CSTYLED */				\
	bgeu,a	.+8;				\
	ld	[scr1 + TRAPTR_FIRST], ptr;	\
	set	panicstr, scr2;			\
	ld	[scr2], scr2;			\
	tst	scr2;				\
	/* CSTYLED */				\
	bz,a	.+8;				\
	st	ptr, [scr1]

/*
 * Macro to restore the %psr (thus enabling traps) while preserving
 * cpu_base_spl.  Note that the actual write to the %psr is broken into
 * two writes to avoid the IU bug (one cannot raise PIL and enable traps
 * in a single write to the %psr).
 */
#define	TRACE_RESTORE_PSR(old, scr1, scr2)	\
	andn	old, PSR_ET, old;		\
	ld	[THREAD_REG + T_CPU], scr1;	\
	ld	[scr1 + CPU_BASE_SPL], scr1;	\
	and	old, PSR_PIL, scr2;		\
	subcc	scr1, scr2, scr1;		\
	/* CSTYLED */				\
	bg,a	9f;				\
	add	old, scr1, old;			\
9:	mov	old, %psr;			\
	wr	old, PSR_ET, %psr;		\
	nop;					\
	nop;					\
	nop

/*
 * Trace macro for underflow or overflow trap handler
 */
#ifdef TRAPTRACE

#define	TRACE_UNFL(code, addr, scr1, scr2, scr3) \
	TRACE_PTR(scr1, scr2);			\
	set	code, scr2;			\
	st	scr2, [scr1 + TRAP_ENT_TBR];	\
	mov	%psr, scr2;			\
	st	scr2, [scr1 + TRAP_ENT_PSR];	\
	st	%g0, [scr1 + TRAP_ENT_PC];	\
	st	addr, [scr1 + TRAP_ENT_SP];	\
	st	%g0, [scr1 + TRAP_ENT_G7];	\
	TRACE_NEXT(scr1, scr2, scr3)

#else	/* TRAPTRACE */

#define	TRACE_UNFL(code, addr, scr1, scr2, scr3)

#endif	/* TRAPTRACE */

#define	TRACE_OVFL	TRACE_UNFL	/* overflow trace is the same */

#endif	/* _ASM */

/*
 * Trap trace codes used in place of a %tbr value when more than one
 * entry is made by a trap.  The general scheme is that the trap-type is
 * in the same position as in the TBR, and the low-order bits indicate
 * which precise entry is being made.
 */
#define	TT_OV_USR	0x051	/* overflow to user address in %sp */
#define	TT_OV_SYS	0x052	/* overflow to system address in %sp */
#define	TT_OV_SHR	0x053	/* overflow of shared window to user */
#define	TT_OV_SHRK	0x054	/* overflow of shared window to system */
#define	TT_OV_BUF	0x055	/* overflow from user of user window to PCB */
#define	TT_OV_BUFK	0x056	/* overflow from kernel of user window to PCB */

#define	TT_UF_USR	0x061	/* underflow of user window */
#define	TT_UF_SYS	0x062	/* underflow of kernel window */
#define	TT_UF_FAULT	0x063	/* underflow of user window had fault */

#define	TT_SC_RET	0x881	/* system call normal return */
#define	TT_SC_POST	0x882	/* system call return after post_syscall */
#define	TT_SC_TRAP	0x883	/* system call return calling trap */

#define	TT_SYS_RTT	0x6666	/* return from trap */
#define	TT_SYS_RTTU	0x7777	/* return from trap to user */

#define	TT_INTR_ENT	-1	/* interrupt entry */
#define	TT_INTR_RET	-2	/* interrupt return */
#define	TT_INTR_RET2	-3	/* interrupt return */
#define	TT_INTR_EXIT	0x8888	/* interrupt thread exit (no pinned thread) */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_TRAPTRACE_H */
