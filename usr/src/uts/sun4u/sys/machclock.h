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
 * Copyright (c) 2005, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#ifndef _SYS_MACHCLOCK_H
#define	_SYS_MACHCLOCK_H

#ifdef	__cplusplus
extern "C" {
#endif

#ifdef _ASM
/*
 * Macro to clear the NPT (non-privileged trap) bit in the %tick/%stick
 * register.  Uses %g1-%g4.
 */
#define	CLEARTICKNPT				\
	sethi	%hi(cpu_clearticknpt), %g1;	\
	jmp	%g1 + %lo(cpu_clearticknpt);	\
	rd	%pc, %g4

#define	RD_TICK_NO_SUSPEND_CHECK(out, scr1)	\
	rdpr	%tick, out;			\
	sllx	out, 1, out;			\
	srlx	out, 1, out;

#define	RD_TICK(out, scr1, scr2, label)		\
	RD_TICK_NO_SUSPEND_CHECK(out, scr1);

/*
 * These macros on sun4u read the %tick register, due to :
 * - %stick does not have enough precision, it's very low frequency
 * - %stick accesses are very slow on UltraSPARC IIe
 * Instead, consumers read %tick and scale it by the current stick/tick ratio.
 * This only works because all cpus in a system change clock ratios
 * synchronously and the changes are all initiated by the kernel.
 */
#define	RD_CLOCK_TICK(out, scr1, scr2, label)	\
/* CSTYLED */					\
	RD_TICK(out,scr1,scr2,label)

#define	RD_CLOCK_TICK_NO_SUSPEND_CHECK(out, scr1)	\
/* CSTYLED */						\
	RD_TICK_NO_SUSPEND_CHECK(out,scr1)

#endif /* _ASM */

#if defined(CPU_MODULE)

/*
 * Constants used to convert hi-res timestamps into nanoseconds
 * (see <sys/clock.h> file for more information)
 */

#if defined(CHEETAH) || defined(HUMMINGBIRD) || defined(OLYMPUS_C)

/*
 * At least 3.9MHz, for slower %stick-based systems.
 */
#define	NSEC_SHIFT	8

#elif defined(SPITFIRE)

/*
 * At least 62.5 MHz, for faster %tick-based systems.
 */
#define	NSEC_SHIFT	4
#define	VTRACE_SHIFT	4

#else
#error "Compiling for CPU_MODULE but no CPU specified"
#endif

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
    gnt1, gnt2) \
5:	sethi	%hi(hres_lock), scr;					\
	lduw	[scr + %lo(hres_lock)], hrlock;	/* load clock lock */	\
	lduw	[scr + %lo(nsec_scale)], nano;	/* tick-to-ns factor */	\
	andn	hrlock, 1, hrlock;  	/* see comments above! */	\
	ldx	[scr + %lo(hres_last_tick)], nslt;			\
	ldn	[scr + %lo(hrestime)], hrestsec; /* load hrestime.sec */\
	add	scr, %lo(hrestime), hrestnsec;				\
	ldn	[hrestnsec + CLONGSIZE], hrestnsec;			\
	GET_NATIVE_TIME(adj, gnt1, gnt2);	/* get current %tick */	\
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
#define	GET_HRTIME(base, now, nslt, scale, scr, hrlock, gnt1, gnt2)	\
5:	sethi	%hi(hres_lock), scr;					\
	lduw	[scr + %lo(hres_lock)], hrlock;	/* load clock lock */	\
	lduw	[scr + %lo(nsec_scale)], scale;	/* tick-to-ns factor */	\
	andn	hrlock, 1, hrlock;  	/* see comments above! */	\
	ldx	[scr + %lo(hres_last_tick)], nslt;			\
	ldx	[scr + %lo(hrtime_base)], base;	/* load hrtime_base */	\
	GET_NATIVE_TIME(now, gnt1, gnt2);	/* get current %tick */	\
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

#ifndef _ASM

#ifdef	_KERNEL

/*
 * Hardware watchdog variables and knobs
 */

#define	CLK_WATCHDOG_DEFAULT	10	/* 10 seconds */

extern int	watchdog_enable;
extern int	watchdog_available;
extern int	watchdog_activated;
extern uint_t	watchdog_timeout_seconds;

/*
 * tod module name and operations
 */
struct tod_ops {
	timestruc_t	(*tod_get)(void);
	void		(*tod_set)(timestruc_t);
	uint_t		(*tod_set_watchdog_timer)(uint_t);
	uint_t		(*tod_clear_watchdog_timer)(void);
	void		(*tod_set_power_alarm)(timestruc_t);
	void		(*tod_clear_power_alarm)(void);
	uint64_t	(*tod_get_cpufrequency)(void);
};

extern struct tod_ops	tod_ops;
extern char		*tod_module_name;

extern uint64_t gettick_counter(void);
#define	CLOCK_TICK_COUNTER() gettick_counter()

/*
 * These defines allow common code to use TOD functions independant
 * of hardware platform.
 */
#define	TODOP_GET(top)		((top).tod_get())
#define	TODOP_SET(top, ts)	((top).tod_set(ts))
#define	TODOP_SETWD(top, nsec)	((top).tod_set_watchdog_timer(nsec))
#define	TODOP_CLRWD(top)	((top).tod_clear_watchdog_timer())
#define	TODOP_SETWAKE(top, ts)	((top).tod_set_power_alarm(ts))
#define	TODOP_CLRWAKE(top)	((top).tod_clear_power_alarm())

#endif	/* _KERNEL */

#endif	/* _ASM */

#ifdef	__cplusplus
}
#endif

#endif	/* !_SYS_MACHCLOCK_H */
