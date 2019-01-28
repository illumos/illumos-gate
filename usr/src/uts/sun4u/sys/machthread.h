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
/*
 * Copyright 2019 Peter Tribble.
 */

#ifndef	_SYS_MACHTHREAD_H
#define	_SYS_MACHTHREAD_H

#include <sys/asi.h>
#include <sys/sun4asi.h>
#include <sys/machasi.h>
#include <sys/bitmap.h>
#include <sys/opl_olympus_regs.h>

#ifdef	__cplusplus
extern "C" {
#endif

#ifdef	_ASM

#define	THREAD_REG	%g7		/* pointer to current thread data */

/*
 * Get the processor implementation from the version register.
 */
#define	GET_CPU_IMPL(out)		\
	rdpr	%ver,	out;		\
	srlx	out, 32, out;		\
	sll	out, 16, out;		\
	srl	out, 16, out;

#ifdef _OPL
/*
 * For OPL platform, we get CPU_INDEX from ASI_EIDR.
 */
#define	CPU_INDEX(r, scr)		\
	ldxa	[%g0]ASI_EIDR, r;	\
	and	r, 0xfff, r


#else /* _OPL */

/*
 * UPA supports up to 32 devices while Safari supports up to
 * 1024 devices (utilizing the SSM protocol). Based upon the
 * value of NCPU, a 5- or 10-bit mask will be needed for
 * extracting the cpu id.
 */
#if NCPU > 32
#define	CPU_MASK	0x3ff
#else
#define	CPU_MASK	0x1f
#endif	/* NCPU > 32 */

/*
 * CPU_INDEX(r, scr)
 * Returns cpu id in r.
 * For UPA based systems, the cpu id corresponds to the mid field in
 * the UPA config register. For Safari based machines, the cpu id
 * corresponds to the aid field in the Safari config register.
 *
 * XXX - scr reg is not used here.
 */
#define	CPU_INDEX(r, scr)		\
	ldxa	[%g0]ASI_UPA_CONFIG, r;	\
	srlx	r, 17, r;		\
	and	r, CPU_MASK, r

#endif	/* _OPL */

/*
 * Given a cpu id extract the appropriate word
 * in the cpuset mask for this cpu id.
 */
#if CPUSET_SIZE > CLONGSIZE
#define	CPU_INDEXTOSET(base, index, scr)	\
	srl	index, BT_ULSHIFT, scr;		\
	and	index, BT_ULMASK, index;	\
	sll	scr, CLONGSHIFT, scr;		\
	add	base, scr, base
#else
#define	CPU_INDEXTOSET(base, index, scr)
#endif	/* CPUSET_SIZE */


/*
 * Assembly macro to find address of the current CPU.
 * Used when coming in from a user trap - cannot use THREAD_REG.
 * Args are destination register and one scratch register.
 */
#define	CPU_ADDR(reg, scr) 		\
	.global	cpu;			\
	CPU_INDEX(scr, reg);		\
	sll	scr, CPTRSHIFT, scr;	\
	set	cpu, reg;		\
	ldn	[reg + scr], reg

#define	CINT64SHIFT	3

/*
 * Assembly macro to find the physical address of the current CPU.
 * All memory references using VA must be limited to nucleus
 * memory to avoid any MMU side effect.
 */
#define	CPU_PADDR(reg, scr)				\
	.global cpu_pa;					\
	CPU_INDEX(scr, reg);				\
	sll	scr, CINT64SHIFT, scr;			\
	set	cpu_pa, reg;				\
	ldx	[reg + scr], reg

#endif	/* _ASM */

/*
 * If a high level trap handler decides to call sys_trap() to execute some
 * base level code, context and other registers must be set to proper
 * values to run kernel. This is true for most part of the kernel, except
 * for user_rtt, a substantial part of which is executed with registers
 * ready to run user code. The following macro may be used to detect this
 * condition and handle it. Please note that, in general, we can't restart
 * arbitrary piece of code running at tl > 0; user_rtt is a special case
 * that can be handled.
 *
 * Entry condition:
 *
 * %tl = 2
 * pstate.ag = 1
 *
 * Register usage:
 *
 * scr1, scr2 - destroyed
 * normal %g5 and %g6 - destroyed
 *
 */
/* BEGIN CSTYLED */
#define	RESET_USER_RTT_REGS(scr1, scr2, label)				\
	/*								\
	 * do nothing if %tl != 2. this an attempt to stop this		\
	 * piece of code from executing more than once before going	\
	 * back to TL=0. more specifically, the changes we are doing	\
	 * to %wstate, %canrestore and %otherwin can't be done more	\
	 * than once before going to TL=0. note that it is okay to	\
	 * execute this more than once if we restart at user_rtt and	\
	 * come back from there.					\
	 */								\
	rdpr	%tl, scr1;						\
	cmp	scr1, 2;						\
	bne,a,pn %xcc, label;						\
	nop;								\
	/*								\
	 * read tstate[2].%tpc. do nothing if it is not			\
	 * between rtt_ctx_start and rtt_ctx_end.			\
	 */								\
	rdpr	%tpc, scr1;						\
	set	rtt_ctx_end, scr2;					\
	cmp	scr1, scr2;						\
	bgu,a,pt %xcc, label;						\
	nop;								\
	set	rtt_ctx_start, scr2;					\
	cmp	scr1, scr2;						\
	blu,a,pt %xcc, label;						\
	nop;								\
	/*								\
	 * pickup tstate[2].cwp						\
	 */								\
	rdpr	%tstate, scr1;						\
	and	scr1, TSTATE_CWP, scr1;					\
	/*								\
	 * set tstate[1].cwp to tstate[2].cwp. fudge			\
	 * tstate[1].tpc and tstate[1].tnpc to restart			\
	 * user_rtt.							\
	 */								\
	wrpr	%g0, 1, %tl;						\
	set	TSTATE_KERN | TSTATE_IE, scr2;				\
	or	scr1, scr2, scr2;					\
	wrpr    %g0, scr2, %tstate;					\
	set	user_rtt, scr1;						\
	wrpr	%g0, scr1, %tpc;					\
	add	scr1, 4, scr1;						\
	wrpr	%g0, scr1, %tnpc;					\
	/*								\
	 * restore %tl							\
	 */								\
	wrpr	%g0, 2, %tl;						\
	/*								\
	 * set %wstate							\
	 */								\
	rdpr	%wstate, scr1;						\
	sllx	scr1, WSTATE_SHIFT, scr1;				\
	wrpr    scr1, WSTATE_K64, %wstate;				\
	/*								\
	 * setup window registers					\
	 * %cleanwin <-- nwin - 1					\
	 * %otherwin <-- %canrestore					\
	 * %canrestore <-- 0						\
	 */								\
	sethi   %hi(nwin_minus_one), scr1;				\
	ld	[scr1 + %lo(nwin_minus_one)], scr1;			\
	wrpr    %g0, scr1, %cleanwin;					\
	rdpr	%canrestore, scr1;					\
	wrpr	%g0, scr1, %otherwin;					\
	wrpr	%g0, 0, %canrestore;					\
	/*								\
	 * set THREAD_REG, as we have restored user			\
	 * registers in user_rtt. we trash %g5 and %g6			\
	 * in the process.						\
	 */								\
	rdpr    %pstate, scr1;						\
	wrpr	scr1, PSTATE_AG, %pstate;				\
	/*								\
	 * using normal globals now					\
	 */								\
	CPU_ADDR(%g5, %g6);						\
	ldn	[%g5 + CPU_THREAD], %g6;				\
	mov	%g6, THREAD_REG;					\
	rdpr	%pstate, %g5;						\
	wrpr	%g5, PSTATE_AG, %pstate;				\
	/*								\
	 * back to alternate globals.					\
	 * set PCONTEXT to run kernel.					\
	 * A demap of I/DTLB is required if the nucleus bits differ	\
	 * from kcontextreg.						\
	 */								\
	mov	MMU_PCONTEXT, scr1;					\
	sethi	%hi(kcontextreg), scr2;					\
	ldx     [scr2 + %lo(kcontextreg)], scr2;			\
	ldxa	[scr1]ASI_MMU_CTX, scr1;				\
	xor	scr2, scr1, scr1;					\
	srlx	scr1, CTXREG_NEXT_SHIFT, scr1;				\
	/*								\
	 * If N_pgsz0/1 changed, need to demap.				\
	 */								\
	brz	scr1, label/**/_0;					\
	nop;								\
	mov	DEMAP_ALL_TYPE, scr1;					\
	stxa	%g0, [scr1]ASI_DTLB_DEMAP;				\
	stxa	%g0, [scr1]ASI_ITLB_DEMAP;				\
label/**/_0:								\
	mov	MMU_PCONTEXT, scr1;					\
	stxa    scr2, [scr1]ASI_MMU_CTX;				\
	sethi   %hi(FLUSH_ADDR), scr1;					\
	flush	scr1

/* END CSTYLED */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_MACHTHREAD_H */
