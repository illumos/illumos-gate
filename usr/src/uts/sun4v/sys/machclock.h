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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SYS_MACHCLOCK_H
#define	_SYS_MACHCLOCK_H

#include <sys/intreg.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Tick/Stick Register Access
 *
 * The following assembly language macros are defined for reading
 * the %tick and %stick registers as well as reading and writing
 * the stick compare register. With the exception of trapstat, reads
 * and writes of these registers all take into account an offset
 * value which is added to the hardware counter. By default, this
 * offset is zero. The offsets can only be modified when CPUs are
 * paused and are only intended to be modified during an OS suspend
 * operation.
 *
 * Since the read of the %tick or %stick is not an atomic operation,
 * it is possible for a suspend operation to occur between the read
 * of the hardware register and its offset variable. The default
 * macros here take this into account by comparing the value of the
 * offset variable before and after reading the hardware register.
 * Callers that need to read the %tick register and can guarantee
 * they will not be preempted can use the RD_TICK_NO_SUSPEND_CHECK
 * which does not check for native_tick_offset changing.
 */
#define	RD_STICK(out, scr1, scr2, label)			\
.rd_stick.label:						\
	sethi	%hi(native_stick_offset), scr1;			\
	ldx	[scr1 + %lo(native_stick_offset)], scr2;	\
	rd	STICK, out;					\
	ldx	[scr1 + %lo(native_stick_offset)], scr1;	\
	sub	scr1, scr2, scr2;				\
/* CSTYLED */							\
	brnz,pn	scr2, .rd_stick.label;				\
	sllx	out, 1, out;					\
	srlx	out, 1, out;					\
	add	out, scr1, out

#define	RD_TICK(out, scr1, scr2, label)				\
.rd_tick.label:							\
	sethi	%hi(native_tick_offset), scr1;			\
	ldx	[scr1 + %lo(native_tick_offset)], scr2;		\
	rd	%tick, out;					\
	ldx	[scr1 + %lo(native_tick_offset)], scr1;		\
	sub	scr1, scr2, scr2;				\
/* CSTYLED */							\
	brnz,pn	scr2, .rd_tick.label;				\
	sllx	out, 1, out;					\
	srlx	out, 1, out;					\
	add	out, scr1, out

#define	RD_TICK_NO_SUSPEND_CHECK(out, scr1)			\
	sethi	%hi(native_tick_offset), scr1;			\
	ldx	[scr1 + %lo(native_tick_offset)], scr1;		\
	rd	%tick, out;					\
	sllx	out, 1, out;					\
	srlx	out, 1, out;					\
	add	out, scr1, out

/*
 * Read the %stick register without taking the native_stick_offset
 * into account.
 */
#define	RD_STICK_PHYSICAL(out)					\
	rd	%stick, out

/*
 * Read the %tick register without taking the native_tick_offset
 * into account. Required to be a single instruction, usable in a
 * delay slot.
 */
#define	RD_TICK_PHYSICAL(out)					\
	rd	%tick, out

/*
 * For traptrace, which requires either the %tick or %stick
 * counter depending on the value of a global variable.
 * If the kernel variable passed in as 'use_stick' is non-zero,
 * read the %stick counter into the 'out' register, otherwise,
 * read the %tick counter. Note the label-less branches.
 * We do not check for the tick or stick offset variables changing
 * during the course of the macro's execution and as a result
 * if a suspend operation occurs between the time the offset
 * variable is read and the hardware register is read, we will
 * use an inaccurate traptrace timestamp.
 */
#define	RD_TICKSTICK_FLAG(out, scr1, use_stick)			\
	sethi	%hi(use_stick), scr1;				\
	lduw	[scr1 + %lo(use_stick)], scr1;			\
/* CSTYLED */							\
	brz,a	scr1, .+24;					\
	rd	%tick, out;					\
	sethi	%hi(native_stick_offset), scr1;			\
	ldx	[scr1 + %lo(native_stick_offset)], scr1;	\
	ba	.+16;						\
	rd	STICK, out;					\
	sethi	%hi(native_tick_offset), scr1;			\
	ldx	[scr1 + %lo(native_tick_offset)], scr1;		\
	sllx	out, 1, out;					\
	srlx	out, 1, out;					\
	add	out, scr1, out;

#define	RD_TICKCMPR(out, scr1, scr2, label)			\
.rd_stickcmpr.label: 						\
	sethi	%hi(native_stick_offset), scr1;			\
	ldx	[scr1 + %lo(native_stick_offset)], scr2;	\
	rd	STICK_COMPARE, out;				\
	ldx	[scr1 + %lo(native_stick_offset)], scr1;	\
	sub	scr1, scr2, scr2;				\
/* CSTYLED */							\
	brnz,pn	scr2, .rd_stickcmpr.label;			\
	add	out, scr1, out

#define	WR_TICKCMPR(in, scr1, scr2, label)			\
	sethi	%hi(native_stick_offset), scr1;			\
	ldx	[scr1 + %lo(native_stick_offset)], scr1;	\
	sub	in, scr1, scr1;					\
	wr	scr1, STICK_COMPARE

#define	GET_NATIVE_TIME(out, scr1, scr2, label)			\
/* CSTYLED */							\
	RD_STICK(out,scr1,scr2,label)

/*
 * Sun4v processors come up with NPT cleared and there is no need to
 * clear it again. Also, clearing of the NPT cannot be done atomically
 * on a CMT processor.
 */
#define	CLEARTICKNPT

#if defined(CPU_MODULE)

/*
 * Constants used to convert hi-res timestamps into nanoseconds
 * (see <sys/clock.h> file for more information)
 */

/*
 * At least 62.5 MHz, for faster %tick-based systems.
 */
#define	NSEC_SHIFT	4

/*
 * NOTE: the macros below assume that the various time-related variables
 * (hrestime, hrestime_adj, hres_last_tick, timedelta, nsec_scale, etc)
 * are all stored together on a 64-byte boundary.  The primary motivation
 * is cache performance, but we also take advantage of a convenient side
 * effect: these variables all have the same high 22 address bits, so only
 * one sethi is needed to access them all.
 */

/*
 * GET_HRESTIME() returns the value of hrestime, hrestime_adj and the
 * number of nanoseconds since the last clock tick ('nslt').  It also
 * sets 'nano' to the value NANOSEC (one billion).
 *
 * This macro assumes that all registers are globals or outs so they can
 * safely contain 64-bit data, and that it's safe to use the label "5:".
 * Further, this macro calls the NATIVE_TIME_TO_NSEC_SCALE which in turn
 * uses the labels "6:" and "7:"; labels "5:", "6:" and "7:" must not
 * be used across invocations of this macro.
 */
#define	GET_HRESTIME(hrestsec, hrestnsec, adj, nslt, nano, scr, hrlock, \
    gnt1, gnt2, label) \
5:	sethi	%hi(hres_lock), scr;					\
	lduw	[scr + %lo(hres_lock)], hrlock;	/* load clock lock */	\
	lduw	[scr + %lo(nsec_scale)], nano;	/* tick-to-ns factor */	\
	andn	hrlock, 1, hrlock;  	/* see comments above! */	\
	ldx	[scr + %lo(hres_last_tick)], nslt;			\
	ldn	[scr + %lo(hrestime)], hrestsec; /* load hrestime.sec */\
	add	scr, %lo(hrestime), hrestnsec;				\
	ldn	[hrestnsec + CLONGSIZE], hrestnsec;			\
/* CSTYLED */ 								\
	GET_NATIVE_TIME(adj,gnt1,gnt2,label); /* get current %stick */	\
	subcc	adj, nslt, nslt; /* nslt = ticks since last clockint */	\
	movneg	%xcc, %g0, nslt; /* ignore neg delta from tick skew */	\
	ldx	[scr + %lo(hrestime_adj)], adj; /* load hrestime_adj */	\
	/* membar #LoadLoad; (see comment (2) above) */			\
	lduw	[scr + %lo(hres_lock)], scr; /* load clock lock */	\
	NATIVE_TIME_TO_NSEC_SCALE(nslt, nano, gnt1, NSEC_SHIFT);	\
	sethi	%hi(NANOSEC), nano;					\
	xor	hrlock, scr, scr;					\
/* CSTYLED */ 								\
	brnz,pn	scr, 5b;						\
	or	nano, %lo(NANOSEC), nano;

/*
 * Similar to above, but returns current gethrtime() value in 'base'.
 */
#define	GET_HRTIME(base, now, nslt, scale, scr, hrlock, gnt1, gnt2, label) \
5:	sethi	%hi(hres_lock), scr;					\
	lduw	[scr + %lo(hres_lock)], hrlock;	/* load clock lock */	\
	lduw	[scr + %lo(nsec_scale)], scale;	/* tick-to-ns factor */	\
	andn	hrlock, 1, hrlock;  	/* see comments above! */	\
	ldx	[scr + %lo(hres_last_tick)], nslt;			\
	ldx	[scr + %lo(hrtime_base)], base;	/* load hrtime_base */	\
/* CSTYLED */ 								\
	GET_NATIVE_TIME(now,gnt1,gnt2,label); /* get current %stick */	\
	subcc	now, nslt, nslt; /* nslt = ticks since last clockint */	\
	movneg	%xcc, %g0, nslt; /* ignore neg delta from tick skew */	\
	/* membar #LoadLoad; (see comment (2) above) */			\
	ld	[scr + %lo(hres_lock)], scr; /* load clock lock */	\
	NATIVE_TIME_TO_NSEC_SCALE(nslt, scale, gnt1, NSEC_SHIFT);	\
	xor	hrlock, scr, scr;					\
/* CSTYLED */ 								\
	brnz,pn	scr, 5b;						\
	add	base, nslt, base;

#endif /* CPU_MODULE */

#ifdef	__cplusplus
}
#endif

#endif	/* !_SYS_MACHCLOCK_H */
