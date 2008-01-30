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
 */

#ifndef _SYS_TRAPTRACE_H
#define	_SYS_TRAPTRACE_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#define	TRAP_TENABLE_ALL	-1	/* enable all hv traptracing */
#define	TRAP_TDISABLE_ALL	0	/* disable all hv traptracing */
#define	TRAP_TFREEZE_ALL	-1	/* freeze all hv traptracing */
#define	TRAP_TUNFREEZE_ALL	0	/* unfreeze all hv traptracing */

/*
 * Trap tracing. If TRAPTRACE is defined, every trap records info
 * in a circular buffer.  Define TRAPTRACE in Makefile.$ARCH.
 *
 * Trap trace records are TRAP_ENT_SIZE bytes, consisting of the
 * %tick, %tl, %tt, %tpc, %tstate, %sp, and a few other words:
 *
 * struct trap_trace_record {
 *	ushort_t tl, tt;
 *	long	pc;
 *	int64_t	tstate, tick;
 *	long	sp, tr, f1, f2, f3, f4;
 * };
 *
 * Note that for UltraSparc III and beyond %stick is used in place of %tick
 * unless compiled with TRAPTRACE_FORCE_TICK.
 *
 * Auxilliary entries (not of just a trap), have obvious non-%tt values in
 * the TRAP_ENT_TT field
 */

#define	TRAP_TBUF	(2 * PAGESIZE)	/* default size is two pages */

#ifndef	_ASM

/*
 * HV Trap trace header
 */
typedef struct htrap_trace_hdr {
	uint64_t	last_offset;	/* most recently completed entry */
	uint64_t	offset;		/* next entry to be written */
	uint64_t	dummy1;
	uint64_t	dummy2;
	uint64_t	dummy3;
	uint64_t	dummy4;
	uint64_t	dummy5;
	uint64_t	dummy6;
} htrap_trace_hdr_t;

/*
 * HV Trap trace record
 */
struct htrap_trace_record {
	uint8_t		tt_ty;		/* Indicates HV or Guest entry */
	uint8_t		tt_hpstate;	/* Hyper-privilege State */
	uint8_t		tt_tl;		/* Trap level */
	uint8_t		tt_gl;		/* Global register level */
	uint16_t	tt_tt;		/* Trap type */
	uint16_t	tt_tag;		/* Extended Trap Indentifier */
	uint64_t	tt_tstate;	/* Trap state */
	uint64_t	tt_tick;	/* Tick */
	uint64_t	tt_tpc;		/* Trap PC */
	uint64_t	tt_f1;		/* Entry specific */
	uint64_t	tt_f2;		/* Entry specific */
	uint64_t	tt_f3;		/* Entry specific */
	uint64_t	tt_f4;		/* Entry specific */
};

/*
 * Kernel Trap trace record
 */
struct trap_trace_record {
	uint8_t		tt_tl;
	uint8_t		tt_gl;
	uint16_t	tt_tt;
	uintptr_t	tt_tpc;
	uint64_t	tt_tstate;
	uint64_t	tt_tick;
	uintptr_t	tt_sp;
	uintptr_t	tt_tr;
	uintptr_t	tt_f1;
	uintptr_t	tt_f2;
	uintptr_t	tt_f3;
	uintptr_t	tt_f4;
};

#define	TRAP_TSIZE	((TRAP_TBUF / sizeof (struct trap_trace_record)) * \
			sizeof (struct trap_trace_record))

/* Rounding not needed, done for consistency */
#define	HTRAP_TSIZE	((TRAP_TBUF / sizeof (struct htrap_trace_record)) * \
			sizeof (struct htrap_trace_record))

#else

#define	TRAP_TSIZE	((TRAP_TBUF / TRAP_ENT_SIZE) * TRAP_ENT_SIZE)
#define	HTRAP_TSIZE	((TRAP_TBUF / HTRAP_ENT_SIZE) * HTRAP_ENT_SIZE)

#endif

/*
 * Trap tracing buffer header.
 */

#ifndef	_ASM

/*
 * Example buffer header stored in locore.s:
 *
 * (the actual implementation could be .skip TRAPTR_SIZE*NCPU)
 */
typedef union {
    struct {
	caddr_t		vaddr_base;	/* virtual address of top of buffer */
	uint64_t	paddr_base;	/* physical address of buffer */
	uint_t		last_offset;	/* to "know" what trace completed */
	uint_t		offset;		/* current index into buffer (bytes) */
	uint_t		limit;		/* upper limit on index */
	uchar_t		asi;		/* cache for real asi */
	caddr_t		hvaddr_base;	/* HV virtual addr of top of buffer */
	uint64_t	hpaddr_base;	/* HV physical addr of buffer */
	uint_t		hlimit;		/* HV upper limit on index */
	} d;
    char		cache_linesize[64];
} TRAP_TRACE_CTL;

#ifdef _KERNEL

extern TRAP_TRACE_CTL	trap_trace_ctl[];	/* allocated in locore.s */
extern int		trap_trace_bufsize;	/* default buffer size */
extern char		trap_tr0[];		/* prealloc buf for boot cpu */
extern int		trap_freeze;		/* freeze the trap trace */
extern caddr_t		ttrace_buf;		/* kmem64 buffer */
extern int		ttrace_index;		/* index used */
extern size_t		calc_traptrace_sz(void);

extern int		htrap_trace_bufsize;	/* default hv buffer size */
extern int		mach_htraptrace_enable;
extern void mach_htraptrace_setup(int);
extern void mach_htraptrace_configure(int);
extern void mach_htraptrace_cleanup(int);

#endif

/*
 * freeze the trap trace
 */
#define	TRAPTRACE_FREEZE	trap_freeze = 1;
#define	TRAPTRACE_UNFREEZE	trap_freeze = 0;

#else /* _ASM */

#include <sys/machthread.h>

/*
 * Offsets of words in trap_trace_ctl:
 */
/*
 * XXX This should be done with genassym
 */
#define	TRAPTR_VBASE	0		/* virtual address of buffer */
#define	TRAPTR_LAST_OFFSET 16		/* last completed trace entry */
#define	TRAPTR_OFFSET	20		/* next trace entry pointer */
#define	TRAPTR_LIMIT	24		/* pointer past end of buffer */
#define	TRAPTR_PBASE	8		/* start of buffer */
#define	TRAPTR_ASIBUF	28		/* cache of current asi */

#define	TRAPTR_HVBASE	32		/* HV virtual address of buffer */
#define	TRAPTR_HPBASE	40		/* HV start of buffer */
#define	TRAPTR_HLIMIT	48		/* HV pointer past end of buffer */

#define	TRAPTR_SIZE_SHIFT	6	/* shift count -- per CPU indexing */
#define	TRAPTR_SIZE		(1<<TRAPTR_SIZE_SHIFT)

#define	TRAPTR_ASI	ASI_MEM		/* ASI to use for TRAPTR access */

/*
 * Use new %stick register for UltraSparc III and beyond for
 * sane debugging of mixed speed CPU systems. Use TRAPTRACE_FORCE_TICK
 * for finer granularity on same speed systems.
 *
 * Note the label-less branches used due to contraints of where
 * and when trap trace macros are used.
 */
#ifdef	TRAPTRACE_FORCE_TICK
#define	GET_TRACE_TICK(reg)				\
	rdpr	%tick, reg;
#else
#define	GET_TRACE_TICK(reg)				\
	sethi	%hi(traptrace_use_stick), reg;		\
	lduw	[reg + %lo(traptrace_use_stick)], reg;	\
	/* CSTYLED */					\
        brz,a	reg, .+12;				\
	rdpr	%tick, reg;				\
	rd	%asr24, reg;
#endif

/*
 * TRACE_PTR(ptr, scr1) - get trap trace entry physical pointer.
 *	ptr is the register to receive the trace pointer.
 *	scr1 is a different register to be used as scratch.
 * TRACING now needs a known processor state.  Hence the assertion.
 *	NOTE: this caches and resets %asi
 */
#define	TRACE_PTR(ptr, scr1)				\
	sethi	%hi(trap_freeze), ptr;			\
	ld	[ptr + %lo(trap_freeze)], ptr;		\
	/* CSTYLED */					\
	brnz,pn	ptr, .+20; /* skip assertion */		\
	rdpr	%pstate, scr1;				\
	andcc	scr1, PSTATE_IE | PSTATE_AM, scr1;	\
	/* CSTYLED */					\
	bne,a,pn %icc, trace_ptr_panic;			\
	rd	%pc, %g1;				\
	CPU_INDEX(scr1, ptr);				\
	sll	scr1, TRAPTR_SIZE_SHIFT, scr1;		\
	set	trap_trace_ctl, ptr; 			\
	add	ptr, scr1, scr1;			\
	rd	%asi, ptr;				\
	stb	ptr, [scr1 + TRAPTR_ASIBUF];		\
	sethi	%hi(trap_freeze), ptr;			\
	ld	[ptr + %lo(trap_freeze)], ptr;		\
	/* CSTYLED */					\
	brnz,pn	ptr, .+20; /* skip assertion */		\
	ld	[scr1 + TRAPTR_LIMIT], ptr;		\
	tst	ptr;					\
	/* CSTYLED */					\
	be,a,pn	%icc, trace_ptr_panic;			\
	rd	%pc, %g1;				\
	ldx	[scr1 + TRAPTR_PBASE], ptr;		\
	ld	[scr1 + TRAPTR_OFFSET], scr1;		\
	wr	%g0, TRAPTR_ASI, %asi;			\
	add	ptr, scr1, ptr;

/*
 * TRACE_NEXT(scr1, scr2, scr3) - advance the trap trace pointer.
 *	scr1, scr2, scr3 are scratch registers.
 *	This routine will skip updating the trap pointers if the
 *	global freeze register is set (e.g. in panic).
 *	(we also restore the asi register)
 */
#define	TRACE_NEXT(scr1, scr2, scr3)			\
	CPU_INDEX(scr2, scr1);				\
	sll	scr2, TRAPTR_SIZE_SHIFT, scr2;		\
	set	trap_trace_ctl, scr1; 			\
	add	scr1, scr2, scr2;			\
	ldub	[scr2 + TRAPTR_ASIBUF], scr1;		\
	wr	%g0, scr1, %asi;			\
	sethi	%hi(trap_freeze), scr1;			\
	ld	[scr1 + %lo(trap_freeze)], scr1;	\
	/* CSTYLED */					\
	brnz	scr1, .+36; /* skip update on freeze */	\
	ld	[scr2 + TRAPTR_OFFSET], scr1;		\
	ld	[scr2 + TRAPTR_LIMIT], scr3;		\
	st	scr1, [scr2 + TRAPTR_LAST_OFFSET];	\
	add	scr1, TRAP_ENT_SIZE, scr1;		\
	sub	scr3, TRAP_ENT_SIZE, scr3;		\
	cmp	scr1, scr3;				\
	movge	%icc, 0, scr1;				\
	st	scr1, [scr2 + TRAPTR_OFFSET];

/*
 * macro to save %tl, %gl to trap trace record at addr
 */
#define	TRACE_SAVE_TL_GL_REGS(addr, scr1)		\
	rdpr	%tl, scr1;				\
	stba	scr1, [addr + TRAP_ENT_TL]%asi;		\
	rdpr	%gl, scr1;				\
	stba	scr1, [addr + TRAP_ENT_GL]%asi

/*
 * macro to save tl to trap trace record at addr
 */
#define	TRACE_SAVE_TL_VAL(addr, tl)			\
	stba	tl, [addr + TRAP_ENT_TL]%asi

/*
 * macro to save gl to trap trace record at addr
 */
#define	TRACE_SAVE_GL_VAL(addr, gl)			\
	stba	gl, [addr + TRAP_ENT_GL]%asi


/*
 * Trace macro for sys_trap return entries:
 *	prom_rtt, priv_rtt, and user_rtt
 *	%l7 - regs
 *	%l6 - trap %pil for prom_rtt and priv_rtt; THREAD_REG for user_rtt
 */
#define	TRACE_RTT(code, scr1, scr2, scr3, scr4)		\
	rdpr	%pstate, scr4;				\
	andn	scr4, PSTATE_IE | PSTATE_AM, scr3;	\
	wrpr	%g0, scr3, %pstate;			\
	TRACE_PTR(scr1, scr2);				\
	GET_TRACE_TICK(scr2);				\
	stxa	scr2, [scr1 + TRAP_ENT_TICK]%asi;	\
	TRACE_SAVE_TL_GL_REGS(scr1, scr2);		\
	set	code, scr2;				\
	stha	scr2, [scr1 + TRAP_ENT_TT]%asi;		\
	ldn	[%l7 + PC_OFF], scr2;			\
	stna	scr2, [scr1 + TRAP_ENT_TPC]%asi;	\
	ldx	[%l7 + TSTATE_OFF], scr2;		\
	stxa	scr2, [scr1 + TRAP_ENT_TSTATE]%asi;	\
	stna	%sp, [scr1 + TRAP_ENT_SP]%asi;		\
	stna	%l6, [scr1 + TRAP_ENT_TR]%asi;		\
	stna	%l7, [scr1 + TRAP_ENT_F1]%asi;		\
	ldn	[THREAD_REG + T_CPU], scr2;		\
	ld	[scr2 + CPU_BASE_SPL], scr2;		\
	stna	scr2, [scr1 + TRAP_ENT_F2]%asi;		\
	stna	%g0, [scr1 + TRAP_ENT_F3]%asi;		\
	rdpr	%cwp, scr2;				\
	stna	scr2, [scr1 + TRAP_ENT_F4]%asi;		\
	TRACE_NEXT(scr1, scr2, scr3);			\
	wrpr	%g0, scr4, %pstate

/*
 * Trace macro for spill and fill trap handlers
 *	tl and tt fields indicate which spill handler is entered
 */
#define	TRACE_WIN_INFO(code, scr1, scr2, scr3)		\
	TRACE_PTR(scr1, scr2);				\
	GET_TRACE_TICK(scr2);				\
	stxa	scr2, [scr1 + TRAP_ENT_TICK]%asi;	\
	TRACE_SAVE_TL_GL_REGS(scr1, scr2);		\
	rdpr	%tt, scr2;				\
	set	code, scr3;				\
	or	scr2, scr3, scr2;			\
	stha	scr2, [scr1 + TRAP_ENT_TT]%asi;		\
	rdpr	%tstate, scr2;				\
	stxa	scr2, [scr1 + TRAP_ENT_TSTATE]%asi;	\
	stna	%sp, [scr1 + TRAP_ENT_SP]%asi;		\
	rdpr	%tpc, scr2;				\
	stna	scr2, [scr1 + TRAP_ENT_TPC]%asi;	\
	set	TT_FSPILL_DEBUG, scr2;			\
	stna	scr2, [scr1 + TRAP_ENT_TR]%asi;		\
	rdpr	%pstate, scr2;				\
	stna	scr2, [scr1 + TRAP_ENT_F1]%asi;		\
	rdpr	%cwp, scr2;				\
	sll	scr2, 24, scr2;				\
	rdpr	%cansave, scr3;				\
	sll	scr3, 16, scr3;				\
	or	scr2, scr3, scr2;			\
	rdpr	%canrestore, scr3;			\
	or	scr2, scr3, scr2;			\
	stna	scr2, [scr1 + TRAP_ENT_F2]%asi;		\
	rdpr	%otherwin, scr2;			\
	sll	scr2, 24, scr2;				\
	rdpr	%cleanwin, scr3;			\
	sll	scr3, 16, scr3;				\
	or	scr2, scr3, scr2;			\
	rdpr	%wstate, scr3;				\
	or	scr2, scr3, scr2;			\
	stna	scr2, [scr1 + TRAP_ENT_F3]%asi;		\
	stna	%o7, [scr1 + TRAP_ENT_F4]%asi;		\
	TRACE_NEXT(scr1, scr2, scr3)

#ifdef TRAPTRACE

#define	FAULT_WINTRACE(scr1, scr2, scr3, type)		\
	TRACE_PTR(scr1, scr2);				\
	GET_TRACE_TICK(scr2);				\
	stxa	scr2, [scr1 + TRAP_ENT_TICK]%asi;	\
	TRACE_SAVE_TL_GL_REGS(scr1, scr2);		\
	set	type, scr2;				\
	stha	scr2, [scr1 + TRAP_ENT_TT]%asi;		\
	rdpr	%tpc, scr2;				\
	stna	scr2, [scr1 + TRAP_ENT_TPC]%asi;	\
	rdpr	%tstate, scr2;				\
	stxa	scr2, [scr1 + TRAP_ENT_TSTATE]%asi;	\
	stna	%sp, [scr1 + TRAP_ENT_SP]%asi;		\
	stna	%g0, [scr1 + TRAP_ENT_TR]%asi;		\
	stna	%g0, [scr1 + TRAP_ENT_F1]%asi;		\
	stna	%g4, [scr1 + TRAP_ENT_F2]%asi;		\
	rdpr	%pil, scr2;				\
	stna	scr2, [scr1 + TRAP_ENT_F3]%asi;		\
	stna	%g0, [scr1 + TRAP_ENT_F4]%asi;		\
	TRACE_NEXT(scr1, scr2, scr3)

#define	SYSTRAP_TT	0x1300

#define	SYSTRAP_TRACE(scr1, scr2, scr3)			\
	TRACE_PTR(scr1, scr2);				\
	GET_TRACE_TICK(scr2);				\
	stxa	scr2, [scr1 + TRAP_ENT_TICK]%asi;	\
	TRACE_SAVE_TL_GL_REGS(scr1, scr2);		\
	set	SYSTRAP_TT, scr3;			\
	rdpr	%tt, scr2;				\
	or	scr3, scr2, scr2;			\
	stha	scr2, [scr1 + TRAP_ENT_TT]%asi;		\
	rdpr	%tpc, scr2;				\
	stna	scr2, [scr1 + TRAP_ENT_TPC]%asi;	\
	rdpr	%tstate, scr2;				\
	stxa	scr2, [scr1 + TRAP_ENT_TSTATE]%asi;	\
	stna	%g1, [scr1 + TRAP_ENT_SP]%asi;		\
	stna	%g2, [scr1 + TRAP_ENT_TR]%asi;		\
	stna	%g3, [scr1 + TRAP_ENT_F1]%asi;		\
	stna	%g4, [scr1 + TRAP_ENT_F2]%asi;		\
	rdpr	%pil, scr2;				\
	stna	scr2, [scr1 + TRAP_ENT_F3]%asi;		\
	rdpr	%cwp, scr2;				\
	stna	scr2, [scr1 + TRAP_ENT_F4]%asi;		\
	TRACE_NEXT(scr1, scr2, scr3)

#else /* TRAPTRACE */

#define	FAULT_WINTRACE(scr1, scr2, scr3, type)
#define	SYSTRAP_TRACE(scr1, scr2, scr3)

#endif /* TRAPTRACE */

#endif	/* _ASM */

/*
 * Trap trace codes used in place of a %tbr value when more than one
 * entry is made by a trap.  The general scheme is that the trap-type is
 * in the same position as in the TT, and the low-order bits indicate
 * which precise entry is being made.
 */

#define	TT_F32_SN0	0x1084
#define	TT_F64_SN0	0x1088
#define	TT_F32_NT0	0x1094
#define	TT_F64_NT0	0x1098
#define	TT_F32_SO0	0x10A4
#define	TT_F64_SO0	0x10A8
#define	TT_F32_FN0	0x10C4
#define	TT_F64_FN0	0x10C8
#define	TT_F32_SN1	0x1284
#define	TT_F64_SN1	0x1288
#define	TT_F32_NT1	0x1294
#define	TT_F64_NT1	0x1298
#define	TT_F32_SO1	0x12A4
#define	TT_F64_SO1	0x12A8
#define	TT_F32_FN1	0x12C4
#define	TT_F64_FN1	0x12C8
#define	TT_RTT_FN1	0x12DD

#define	TT_SC_ENTR	0x880	/* enter system call */
#define	TT_SC_RET	0x881	/* system call normal return */

#define	TT_SYS_RTT_PROM	0x5555	/* return from trap to prom */
#define	TT_SYS_RTT_PRIV	0x6666	/* return from trap to privilege */
#define	TT_SYS_RTT_USER	0x7777	/* return from trap to user */

#define	TT_INTR_EXIT	0x8888	/* interrupt thread exit (no pinned thread) */
#define	TT_FSPILL_DEBUG	0x9999	/* fill/spill debugging */

#define	TT_SERVE_INTR	0x6000	/* SERVE_INTR */
#define	TT_XCALL	0xd000	/* xcall/xtrap */
#define	TT_XCALL_CONT	0xdc00	/* continuation of an xcall/xtrap record */

#define	TT_MMU_MISS	0x200	/* or'd into %tt to indicate a miss */
#define	TT_MMU_EXEC	0x400	/* or'd into %tt to indicate exec_fault */


#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_TRAPTRACE_H */
