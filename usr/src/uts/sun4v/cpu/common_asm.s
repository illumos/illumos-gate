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

#if !defined(lint)
#include "assym.h"
#endif

/*
 * General assembly language routines.
 * It is the intent of this file to contain routines that are
 * specific to cpu architecture.
 */

/*
 * WARNING: If you add a fast trap handler which can be invoked by a
 * non-privileged user, you may have to use the FAST_TRAP_DONE macro
 * instead of "done" instruction to return back to the user mode. See
 * comments for the "fast_trap_done" entry point for more information.
 */
#define	FAST_TRAP_DONE	\
	ba,a	fast_trap_done

#include <sys/machclock.h>
#include <sys/clock.h>

#if defined(lint)
#include <sys/types.h>
#include <sys/scb.h>
#include <sys/systm.h>
#include <sys/regset.h>
#include <sys/sunddi.h>
#include <sys/lockstat.h>
#endif	/* lint */


#include <sys/asm_linkage.h>
#include <sys/privregs.h>
#include <vm/hat_sfmmu.h>
#include <sys/machparam.h>	/* To get SYSBASE and PAGESIZE */
#include <sys/machthread.h>
#include <sys/clock.h>
#include <sys/intreg.h>
#include <sys/psr_compat.h>
#include <sys/isa_defs.h>
#include <sys/dditypes.h>
#include <sys/intr.h>
#include <sys/hypervisor_api.h>

#if !defined(lint)
#include "assym.h"
#endif

#define	ICACHE_FLUSHSZ	0x20

#if defined(lint)
/*
 * Softint generated when counter field of tick reg matches value field 
 * of tick_cmpr reg
 */
/*ARGSUSED*/
void
tickcmpr_set(uint64_t clock_cycles)
{}

#else   /* lint */

	ENTRY_NP(tickcmpr_set)
	! get 64-bit clock_cycles interval
	mov	%o0, %o2
	mov	8, %o3			! A reasonable initial step size
1:
	WR_TICKCMPR(%o2,%o4,%o5,__LINE__)	! Write to TICK_CMPR

	GET_NATIVE_TIME(%o0,%o4,%o5,__LINE__)	! Read %tick to confirm the
						! value we wrote was in the
						! future.

	cmp	%o2, %o0		! If the value we wrote was in the
	bg,pt	%xcc, 2f		!   future, then blow out of here.
	  sllx	%o3, 1, %o3		! If not, then double our step size,
	ba,pt	%xcc, 1b		!   and take another lap.
	  add	%o0, %o3, %o2		!
2:
	retl
	  nop
	SET_SIZE(tickcmpr_set)

#endif  /* lint */

#if defined(lint)

void
tickcmpr_disable(void)
{}

#else

	ENTRY_NP(tickcmpr_disable)
	mov	1, %g1
	sllx	%g1, TICKINT_DIS_SHFT, %o0
	WR_TICKCMPR(%o0,%o4,%o5,__LINE__)	! Write to TICK_CMPR
	retl
	  nop
	SET_SIZE(tickcmpr_disable)

#endif

#if defined(lint)

/*
 * tick_write_delta() is intended to increment %stick by the specified delta,
 * but %stick is only writeable in hyperprivileged mode and at present there
 * is no provision for this. tick_write_delta is called by the cylic subsystem
 * if a negative %stick delta is observed after cyclic processing is resumed
 * after an event such as an OS suspend/resume. On sun4v, the suspend/resume
 * routines should adjust the %stick offset preventing the cyclic subsystem
 * from detecting a negative delta. If a negative delta is detected, panic the
 * system. The negative delta could be caused by improper %stick
 * synchronization after a suspend/resume.
 */

/*ARGSUSED*/
void
tick_write_delta(uint64_t delta)
{}

#else	/* lint */

	.seg	".text"
tick_write_delta_panic:
	.asciz	"tick_write_delta: not supported, delta: 0x%lx"

	ENTRY_NP(tick_write_delta)
	sethi	%hi(tick_write_delta_panic), %o1
        save    %sp, -SA(MINFRAME), %sp ! get a new window to preserve caller
	mov	%i0, %o1
	call	panic
	  or	%i1, %lo(tick_write_delta_panic), %o0
	/*NOTREACHED*/
	retl
	  nop
#endif

#if defined(lint)
/*
 *  return 1 if disabled
 */

int
tickcmpr_disabled(void)
{ return (0); }

#else   /* lint */

	ENTRY_NP(tickcmpr_disabled)
	RD_TICKCMPR(%g1,%o0,%o1,__LINE__)
	retl
	  srlx	%g1, TICKINT_DIS_SHFT, %o0
	SET_SIZE(tickcmpr_disabled)

#endif  /* lint */

/*
 * Get current tick
 */
#if defined(lint)

u_longlong_t
gettick(void)
{ return (0); }

u_longlong_t
randtick(void)
{ return (0); }

#else   /* lint */

	ENTRY(gettick)
	ALTENTRY(randtick)
	GET_NATIVE_TIME(%o0,%o2,%o3,__LINE__)
	retl
	  nop
	SET_SIZE(randtick)
	SET_SIZE(gettick)

#endif  /* lint */

/*
 * Get current tick. For trapstat use only.
 */
#if defined (lint)

hrtime_t
rdtick()
{ return (0); }

#else
	ENTRY(rdtick)
	retl
	RD_TICK_PHYSICAL(%o0)
	SET_SIZE(rdtick)
#endif /* lint */


/*
 * Return the counter portion of the tick register.
 */

#if defined(lint)

uint64_t
gettick_counter(void)
{ return(0); }

uint64_t
gettick_npt(void)
{ return(0); }

uint64_t
getstick_npt(void)
{ return(0); }

#else	/* lint */

	ENTRY_NP(gettick_counter)
	RD_TICK(%o0,%o1,%o2,__LINE__)
	retl
	nop
	SET_SIZE(gettick_counter)

	ENTRY_NP(gettick_npt)
	RD_TICK_PHYSICAL(%o0)
	retl
	srlx	%o0, 63, %o0
	SET_SIZE(gettick_npt)

	ENTRY_NP(getstick_npt)
	RD_STICK_PHYSICAL(%o0)
	retl
	srlx	%o0, 63, %o0
	SET_SIZE(getstick_npt)
#endif	/* lint */

/*
 * Provide a C callable interface to the trap that reads the hi-res timer.
 * Returns 64-bit nanosecond timestamp in %o0 and %o1.
 */

#if defined(lint)

hrtime_t
gethrtime(void)
{
	return ((hrtime_t)0);
}

hrtime_t
gethrtime_unscaled(void)
{
	return ((hrtime_t)0);
}

hrtime_t
gethrtime_max(void)
{
	return ((hrtime_t)0);
}

void
scalehrtime(hrtime_t *hrt)
{
	*hrt = 0;
}

void
gethrestime(timespec_t *tp)
{
	tp->tv_sec = 0;
	tp->tv_nsec = 0;
}

time_t
gethrestime_sec(void)
{
	return (0);
}

void
gethrestime_lasttick(timespec_t *tp)
{
	tp->tv_sec = 0;
	tp->tv_nsec = 0;
}

/*ARGSUSED*/
void
hres_tick(void)
{
}

void
panic_hres_tick(void)
{
}

#else	/* lint */

	ENTRY_NP(gethrtime)
	GET_HRTIME(%g1,%o0,%o1,%o2,%o3,%o4,%o5,%g2,__LINE__)
							! %g1 = hrtime
	retl
	  mov	%g1, %o0
	SET_SIZE(gethrtime)

	ENTRY_NP(gethrtime_unscaled)
	GET_NATIVE_TIME(%g1,%o2,%o3,__LINE__)	! %g1 = native time
	retl
	  mov	%g1, %o0
	SET_SIZE(gethrtime_unscaled)

	ENTRY_NP(gethrtime_waitfree)
	ALTENTRY(dtrace_gethrtime)
	GET_NATIVE_TIME(%g1,%o2,%o3,__LINE__)	! %g1 = native time
	NATIVE_TIME_TO_NSEC(%g1, %o2, %o3)
	retl
	  mov	%g1, %o0
	SET_SIZE(dtrace_gethrtime)
	SET_SIZE(gethrtime_waitfree)

	ENTRY(gethrtime_max)
	NATIVE_TIME_MAX(%g1)
	NATIVE_TIME_TO_NSEC(%g1, %o0, %o1)

	! hrtime_t's are signed, max hrtime_t must be positive
	mov	-1, %o2
	brlz,a	%g1, 1f
	  srlx	%o2, 1, %g1
1:
	retl
	  mov	%g1, %o0
	SET_SIZE(gethrtime_max)

	ENTRY(scalehrtime)
	ldx	[%o0], %o1
	NATIVE_TIME_TO_NSEC(%o1, %o2, %o3)
	retl
	  stx	%o1, [%o0]
	SET_SIZE(scalehrtime)

/*
 * Fast trap to return a timestamp, uses trap window, leaves traps
 * disabled.  Returns a 64-bit nanosecond timestamp in %o0 and %o1.
 *
 * This is the handler for the ST_GETHRTIME trap.
 */

	ENTRY_NP(get_timestamp)
	GET_HRTIME(%g1,%g2,%g3,%g4,%g5,%o0,%o1,%o2,__LINE__)
	! %g1 = hrtime
	srlx	%g1, 32, %o0				! %o0 = hi32(%g1)
	srl	%g1, 0, %o1				! %o1 = lo32(%g1)
	FAST_TRAP_DONE
	SET_SIZE(get_timestamp)

/*
 * Macro to convert GET_HRESTIME() bits into a timestamp.
 *
 * We use two separate macros so that the platform-dependent GET_HRESTIME()
 * can be as small as possible; CONV_HRESTIME() implements the generic part.
 */
#define	CONV_HRESTIME(hrestsec, hrestnsec, adj, nslt, nano) \
	brz,pt	adj, 3f;		/* no adjustments, it's easy */	\
	add	hrestnsec, nslt, hrestnsec; /* hrest.tv_nsec += nslt */	\
	brlz,pn	adj, 2f;		/* if hrestime_adj negative */	\
	  srlx	nslt, ADJ_SHIFT, nslt;	/* delay: nslt >>= 4 */		\
	subcc	adj, nslt, %g0;		/* hrestime_adj - nslt/16 */	\
	movg	%xcc, nslt, adj;	/* adj by min(adj, nslt/16) */	\
	ba	3f;			/* go convert to sec/nsec */	\
	  add	hrestnsec, adj, hrestnsec; /* delay: apply adjustment */ \
2:	addcc	adj, nslt, %g0;		/* hrestime_adj + nslt/16 */	\
	bge,a,pt %xcc, 3f;		/* is adj less negative? */	\
	  add	hrestnsec, adj, hrestnsec; /* yes: hrest.nsec += adj */	\
	sub	hrestnsec, nslt, hrestnsec; /* no: hrest.nsec -= nslt/16 */ \
3:	cmp	hrestnsec, nano;	/* more than a billion? */	\
	bl,pt	%xcc, 4f;		/* if not, we're done */	\
	  nop;				/* delay: do nothing :( */	\
	add	hrestsec, 1, hrestsec;	/* hrest.tv_sec++; */		\
	sub	hrestnsec, nano, hrestnsec; /* hrest.tv_nsec -= NANOSEC; */	\
	ba,a	3b;			/* check >= billion again */	\
4:

	ENTRY_NP(gethrestime)
	GET_HRESTIME(%o1,%o2,%o3,%o4,%o5,%g1,%g2,%g3,%g4,__LINE__)
	CONV_HRESTIME(%o1, %o2, %o3, %o4, %o5)
	stn	%o1, [%o0]
	retl
	  stn	%o2, [%o0 + CLONGSIZE]
	SET_SIZE(gethrestime)

/*
 * Similar to gethrestime(), but gethrestime_sec() returns current hrestime
 * seconds.
 */
	ENTRY_NP(gethrestime_sec)
	GET_HRESTIME(%o0,%o2,%o3,%o4,%o5,%g1,%g2,%g3,%g4,__LINE__)
	CONV_HRESTIME(%o0, %o2, %o3, %o4, %o5)
	retl					! %o0 current hrestime seconds
	  nop
	SET_SIZE(gethrestime_sec)

/*
 * Returns the hrestime on the last tick.  This is simpler than gethrestime()
 * and gethrestime_sec():  no conversion is required.  gethrestime_lasttick()
 * follows the same locking algorithm as GET_HRESTIME and GET_HRTIME,
 * outlined in detail in clock.h.  (Unlike GET_HRESTIME/GET_HRTIME, we don't
 * rely on load dependencies to effect the membar #LoadLoad, instead declaring
 * it explicitly.)
 */
	ENTRY_NP(gethrestime_lasttick)
	sethi	%hi(hres_lock), %o1
0:
	lduw	[%o1 + %lo(hres_lock)], %o2	! Load lock value
	membar	#LoadLoad			! Load of lock must complete
	andn	%o2, 1, %o2			! Mask off lowest bit	
	ldn	[%o1 + %lo(hrestime)], %g1	! Seconds.
	add	%o1, %lo(hrestime), %o4
	ldn	[%o4 + CLONGSIZE], %g2		! Nanoseconds.
	membar	#LoadLoad			! All loads must complete
	lduw	[%o1 + %lo(hres_lock)], %o3	! Reload lock value
	cmp	%o3, %o2			! If lock is locked or has
	bne	0b				!   changed, retry.
	  stn	%g1, [%o0]			! Delay: store seconds
	retl
	  stn	%g2, [%o0 + CLONGSIZE]		! Delay: store nanoseconds
	SET_SIZE(gethrestime_lasttick)

/*
 * Fast trap for gettimeofday().  Returns a timestruc_t in %o0 and %o1.
 *
 * This is the handler for the ST_GETHRESTIME trap.
 */

	ENTRY_NP(get_hrestime)
	GET_HRESTIME(%o0,%o1,%g1,%g2,%g3,%g4,%g5,%o2,%o3,__LINE__)
	CONV_HRESTIME(%o0, %o1, %g1, %g2, %g3)
	FAST_TRAP_DONE
	SET_SIZE(get_hrestime)

/*
 * Fast trap to return lwp virtual time, uses trap window, leaves traps
 * disabled.  Returns a 64-bit number in %o0:%o1, which is the number
 * of nanoseconds consumed.
 *
 * This is the handler for the ST_GETHRVTIME trap.
 *
 * Register usage:
 *	%o0, %o1 = return lwp virtual time
 * 	%o2 = CPU/thread
 * 	%o3 = lwp
 * 	%g1 = scratch
 * 	%g5 = scratch
 */
	ENTRY_NP(get_virtime)
	GET_NATIVE_TIME(%g5,%g1,%g2,__LINE__)	! %g5 = native time in ticks
	CPU_ADDR(%g2, %g3)			! CPU struct ptr to %g2
	ldn	[%g2 + CPU_THREAD], %g2		! thread pointer to %g2
	ldn	[%g2 + T_LWP], %g3		! lwp pointer to %g3

	/*
	 * Subtract start time of current microstate from time
	 * of day to get increment for lwp virtual time.
	 */
	ldx	[%g3 + LWP_STATE_START], %g1	! ms_state_start
	sub	%g5, %g1, %g5

	/*
	 * Add current value of ms_acct[LMS_USER]
	 */
	ldx	[%g3 + LWP_ACCT_USER], %g1	! ms_acct[LMS_USER]
	add	%g5, %g1, %g5
	NATIVE_TIME_TO_NSEC(%g5, %g1, %o0) 
	
	srl	%g5, 0, %o1			! %o1 = lo32(%g5)
	srlx	%g5, 32, %o0			! %o0 = hi32(%g5)

	FAST_TRAP_DONE
	SET_SIZE(get_virtime)



	.seg	".text"
hrtime_base_panic:
	.asciz	"hrtime_base stepping back"


	ENTRY_NP(hres_tick)
	save	%sp, -SA(MINFRAME), %sp	! get a new window

	sethi	%hi(hrestime), %l4
	ldstub	[%l4 + %lo(hres_lock + HRES_LOCK_OFFSET)], %l5	! try locking
7:	tst	%l5
	bz,pt	%xcc, 8f			! if we got it, drive on
	  ld	[%l4 + %lo(nsec_scale)], %l5	! delay: %l5 = scaling factor
	ldub	[%l4 + %lo(hres_lock + HRES_LOCK_OFFSET)], %l5
9:	tst	%l5
	bz,a,pn	%xcc, 7b
	  ldstub	[%l4 + %lo(hres_lock + HRES_LOCK_OFFSET)], %l5
	ba,pt	%xcc, 9b
	  ldub	[%l4 + %lo(hres_lock + HRES_LOCK_OFFSET)], %l5
8:
	membar	#StoreLoad|#StoreStore

	!
	! update hres_last_tick.  %l5 has the scaling factor (nsec_scale).
	!
	ldx	[%l4 + %lo(hrtime_base)], %g1	! load current hrtime_base
	GET_NATIVE_TIME(%l0,%l3,%l6,__LINE__)	! current native time
	stx	%l0, [%l4 + %lo(hres_last_tick)]! prev = current
	! convert native time to nsecs
	NATIVE_TIME_TO_NSEC_SCALE(%l0, %l5, %l2, NSEC_SHIFT)

	sub	%l0, %g1, %i1			! get accurate nsec delta

	ldx	[%l4 + %lo(hrtime_base)], %l1	
	cmp	%l1, %l0
	bg,pn	%xcc, 9f
	  nop

	stx	%l0, [%l4 + %lo(hrtime_base)]	! update hrtime_base

	!
	! apply adjustment, if any
	!
	ldx	[%l4 + %lo(hrestime_adj)], %l0	! %l0 = hrestime_adj
	brz	%l0, 2f
						! hrestime_adj == 0 ?
						! yes, skip adjustments
	  clr	%l5				! delay: set adj to zero
	tst	%l0				! is hrestime_adj >= 0 ?
	bge,pt	%xcc, 1f			! yes, go handle positive case
	  srl	%i1, ADJ_SHIFT, %l5		! delay: %l5 = adj

	addcc	%l0, %l5, %g0			! hrestime_adj < -adj ?
	bl,pt	%xcc, 2f			! yes, use current adj
	  neg	%l5				! delay: %l5 = -adj
	ba,pt	%xcc, 2f
	  mov	%l0, %l5			! no, so set adj = hrestime_adj
1:
	subcc	%l0, %l5, %g0			! hrestime_adj < adj ?
	bl,a,pt	%xcc, 2f			! yes, set adj = hrestime_adj
	  mov	%l0, %l5			! delay: adj = hrestime_adj
2:
	ldx	[%l4 + %lo(timedelta)], %l0	! %l0 = timedelta
	sub	%l0, %l5, %l0			! timedelta -= adj

	stx	%l0, [%l4 + %lo(timedelta)]	! store new timedelta
	stx	%l0, [%l4 + %lo(hrestime_adj)]	! hrestime_adj = timedelta

	or	%l4, %lo(hrestime), %l2
	ldn	[%l2], %i2			! %i2:%i3 = hrestime sec:nsec
	ldn	[%l2 + CLONGSIZE], %i3
	add	%i3, %l5, %i3			! hrestime.nsec += adj
	add	%i3, %i1, %i3			! hrestime.nsec += nslt

	set	NANOSEC, %l5			! %l5 = NANOSEC
	cmp	%i3, %l5
	bl,pt	%xcc, 5f			! if hrestime.tv_nsec < NANOSEC
	  sethi	%hi(one_sec), %i1		! delay
	add	%i2, 0x1, %i2			! hrestime.tv_sec++
	sub	%i3, %l5, %i3			! hrestime.tv_nsec - NANOSEC
	mov	0x1, %l5
	st	%l5, [%i1 + %lo(one_sec)]
5:
	stn	%i2, [%l2]
	stn	%i3, [%l2 + CLONGSIZE]		! store the new hrestime

	membar	#StoreStore

	ld	[%l4 + %lo(hres_lock)], %i1
	inc	%i1				! release lock
	st	%i1, [%l4 + %lo(hres_lock)]	! clear hres_lock

	ret
	restore

9:
	!
	! release hres_lock
	!
	ld	[%l4 + %lo(hres_lock)], %i1
	inc	%i1
	st	%i1, [%l4 + %lo(hres_lock)]

	sethi	%hi(hrtime_base_panic), %o0
	call	panic
	  or	%o0, %lo(hrtime_base_panic), %o0

	SET_SIZE(hres_tick)

#endif	/* lint */

#if !defined(lint) && !defined(__lint)

	.seg	".text"
kstat_q_panic_msg:
	.asciz	"kstat_q_exit: qlen == 0"

	ENTRY(kstat_q_panic)
	save	%sp, -SA(MINFRAME), %sp
	sethi	%hi(kstat_q_panic_msg), %o0
	call	panic
	  or	%o0, %lo(kstat_q_panic_msg), %o0
	/*NOTREACHED*/
	SET_SIZE(kstat_q_panic)

#define	BRZPN	brz,pn
#define	BRZPT	brz,pt

#define	KSTAT_Q_UPDATE(QOP, QBR, QZERO, QRETURN, QTYPE) \
	ld	[%o0 + QTYPE/**/CNT], %o1;	/* %o1 = old qlen */	\
	QOP	%o1, 1, %o2;			/* %o2 = new qlen */	\
	QBR	%o1, QZERO;			/* done if qlen == 0 */	\
	st	%o2, [%o0 + QTYPE/**/CNT];	/* delay: save qlen */	\
	ldx	[%o0 + QTYPE/**/LASTUPDATE], %o3;			\
	ldx	[%o0 + QTYPE/**/TIME], %o4;	/* %o4 = old time */	\
	ldx	[%o0 + QTYPE/**/LENTIME], %o5;	/* %o5 = old lentime */	\
	sub	%g1, %o3, %o2;			/* %o2 = time delta */	\
	mulx	%o1, %o2, %o3;			/* %o3 = cur lentime */	\
	add	%o4, %o2, %o4;			/* %o4 = new time */	\
	add	%o5, %o3, %o5;			/* %o5 = new lentime */	\
	stx	%o4, [%o0 + QTYPE/**/TIME];	/* save time */		\
	stx	%o5, [%o0 + QTYPE/**/LENTIME];	/* save lentime */	\
QRETURN;								\
	stx	%g1, [%o0 + QTYPE/**/LASTUPDATE]; /* lastupdate = now */

#if !defined(DEBUG)
/*
 * same as KSTAT_Q_UPDATE but without:
 * QBR     %o1, QZERO;
 * to be used only with non-debug build. mimics ASSERT() behaviour.
 */
#define	KSTAT_Q_UPDATE_ND(QOP, QRETURN, QTYPE) \
	ld	[%o0 + QTYPE/**/CNT], %o1;	/* %o1 = old qlen */	\
	QOP	%o1, 1, %o2;			/* %o2 = new qlen */	\
	st	%o2, [%o0 + QTYPE/**/CNT];	/* delay: save qlen */	\
	ldx	[%o0 + QTYPE/**/LASTUPDATE], %o3;			\
	ldx	[%o0 + QTYPE/**/TIME], %o4;	/* %o4 = old time */	\
	ldx	[%o0 + QTYPE/**/LENTIME], %o5;	/* %o5 = old lentime */	\
	sub	%g1, %o3, %o2;			/* %o2 = time delta */	\
	mulx	%o1, %o2, %o3;			/* %o3 = cur lentime */	\
	add	%o4, %o2, %o4;			/* %o4 = new time */	\
	add	%o5, %o3, %o5;			/* %o5 = new lentime */	\
	stx	%o4, [%o0 + QTYPE/**/TIME];	/* save time */		\
	stx	%o5, [%o0 + QTYPE/**/LENTIME];	/* save lentime */	\
QRETURN;								\
	stx	%g1, [%o0 + QTYPE/**/LASTUPDATE]; /* lastupdate = now */
#endif

	.align 16
	ENTRY(kstat_waitq_enter)
	GET_NATIVE_TIME(%g1,%g2,%g3,__LINE__)
	KSTAT_Q_UPDATE(add, BRZPT, 1f, 1:retl, KSTAT_IO_W)
	SET_SIZE(kstat_waitq_enter)

	.align 16
	ENTRY(kstat_waitq_exit)
	GET_NATIVE_TIME(%g1,%g2,%g3,__LINE__)
#if defined(DEBUG)
	KSTAT_Q_UPDATE(sub, BRZPN, kstat_q_panic, retl, KSTAT_IO_W)
#else
	KSTAT_Q_UPDATE_ND(sub, retl, KSTAT_IO_W)
#endif
	SET_SIZE(kstat_waitq_exit)

	.align 16
	ENTRY(kstat_runq_enter)
	GET_NATIVE_TIME(%g1,%g2,%g3,__LINE__)
	KSTAT_Q_UPDATE(add, BRZPT, 1f, 1:retl, KSTAT_IO_R)
	SET_SIZE(kstat_runq_enter)

	.align 16
	ENTRY(kstat_runq_exit)
	GET_NATIVE_TIME(%g1,%g2,%g3,__LINE__)
#if defined(DEBUG)
	KSTAT_Q_UPDATE(sub, BRZPN, kstat_q_panic, retl, KSTAT_IO_R)
#else
	KSTAT_Q_UPDATE_ND(sub, retl, KSTAT_IO_R)
#endif
	SET_SIZE(kstat_runq_exit)

	.align 16
	ENTRY(kstat_waitq_to_runq)
	GET_NATIVE_TIME(%g1,%g2,%g3,__LINE__)
#if defined(DEBUG)
	KSTAT_Q_UPDATE(sub, BRZPN, kstat_q_panic, 1:, KSTAT_IO_W)
#else
	KSTAT_Q_UPDATE_ND(sub, 1:, KSTAT_IO_W)
#endif
	KSTAT_Q_UPDATE(add, BRZPT, 1f, 1:retl, KSTAT_IO_R)
	SET_SIZE(kstat_waitq_to_runq)

	.align 16
	ENTRY(kstat_runq_back_to_waitq)
	GET_NATIVE_TIME(%g1,%g2,%g3,__LINE__)
#if defined(DEBUG)
	KSTAT_Q_UPDATE(sub, BRZPN, kstat_q_panic, 1:, KSTAT_IO_R)
#else
	KSTAT_Q_UPDATE_ND(sub, 1:, KSTAT_IO_R)
#endif
	KSTAT_Q_UPDATE(add, BRZPT, 1f, 1:retl, KSTAT_IO_W)
	SET_SIZE(kstat_runq_back_to_waitq)

#endif /* lint */

#ifdef lint	

int64_t timedelta;
hrtime_t hres_last_tick;
volatile timestruc_t hrestime;
int64_t hrestime_adj;
volatile int hres_lock;
uint_t nsec_scale;
hrtime_t hrtime_base;
int traptrace_use_stick;

#else
	/*
	 *  -- WARNING --
	 *
	 * The following variables MUST be together on a 128-byte boundary.
	 * In addition to the primary performance motivation (having them all
	 * on the same cache line(s)), code here and in the GET*TIME() macros
	 * assumes that they all have the same high 22 address bits (so
	 * there's only one sethi).
	 */
	.seg	".data"
	.global	timedelta, hres_last_tick, hrestime, hrestime_adj
	.global	hres_lock, nsec_scale, hrtime_base, traptrace_use_stick
	.global	nsec_shift, adj_shift, native_tick_offset, native_stick_offset

	/* XXX - above comment claims 128-bytes is necessary */
	.align	64
timedelta:
	.word	0, 0		/* int64_t */
hres_last_tick:
	.word	0, 0		/* hrtime_t */
hrestime:
	.nword	0, 0		/* 2 longs */
hrestime_adj:
	.word	0, 0		/* int64_t */
hres_lock:
	.word	0
nsec_scale:
	.word	0
hrtime_base:
	.word	0, 0
traptrace_use_stick:
	.word	0
nsec_shift:
	.word	NSEC_SHIFT
adj_shift:
	.word	ADJ_SHIFT
	.align	8
native_tick_offset:
	.word	0, 0
	.align	8
native_stick_offset:
	.word	0, 0

#endif


/*
 * drv_usecwait(clock_t n)	[DDI/DKI - section 9F]
 * usec_delay(int n)		[compatibility - should go one day]
 * Delay by spinning.
 *
 * delay for n microseconds.  numbers <= 0 delay 1 usec
 *
 * With UltraSPARC-III the combination of supporting mixed-speed CPUs
 * and variable clock rate for power management requires that we
 * use %stick to implement this routine.
 */

#if defined(lint)

/*ARGSUSED*/
void
drv_usecwait(clock_t n)
{}

/*ARGSUSED*/
void
usec_delay(int n)
{}

#else	/* lint */

	ENTRY(drv_usecwait)
	ALTENTRY(usec_delay)
	brlez,a,pn %o0, 0f
	  mov	1, %o0
0:
	sethi	%hi(sticks_per_usec), %o1
	lduw	[%o1 + %lo(sticks_per_usec)], %o1
	mulx	%o1, %o0, %o1		! Scale usec to ticks
	inc	%o1			! We don't start on a tick edge
	GET_NATIVE_TIME(%o2,%o3,%o4,__LINE__)
	add	%o1, %o2, %o1

1:	cmp	%o1, %o2
	GET_NATIVE_TIME(%o2,%o3,%o4,__LINE__)
	bgeu,pt	%xcc, 1b
	  nop
	retl
	  nop
	SET_SIZE(usec_delay)
	SET_SIZE(drv_usecwait)
#endif	/* lint */

#if defined(lint)

/* ARGSUSED */
void
pil14_interrupt(int level)
{}

#else

/*
 * Level-14 interrupt prologue.
 */
	ENTRY_NP(pil14_interrupt)
	CPU_ADDR(%g1, %g2)
	rdpr	%pil, %g6			! %g6 = interrupted PIL
	stn	%g6, [%g1 + CPU_PROFILE_PIL]	! record interrupted PIL
	rdpr	%tstate, %g6
	rdpr	%tpc, %g5
	btst	TSTATE_PRIV, %g6		! trap from supervisor mode?
	bnz,a,pt %xcc, 1f
	  stn	%g5, [%g1 + CPU_PROFILE_PC]	! if so, record kernel PC
	stn	%g5, [%g1 + CPU_PROFILE_UPC]	! if not, record user PC
	ba	pil_interrupt_common		! must be large-disp branch
	  stn	%g0, [%g1 + CPU_PROFILE_PC]	! zero kernel PC
1:	ba	pil_interrupt_common		! must be large-disp branch
	  stn	%g0, [%g1 + CPU_PROFILE_UPC]	! zero user PC
	SET_SIZE(pil14_interrupt)

	ENTRY_NP(tick_rtt)
	!
	! Load TICK_COMPARE into %o5; if bit 63 is set, then TICK_COMPARE is
	! disabled.  If TICK_COMPARE is enabled, we know that we need to
	! reenqueue the interrupt request structure.  We'll then check TICKINT
	! in SOFTINT; if it's set, then we know that we were in a TICK_COMPARE
	! interrupt.  In this case, TICK_COMPARE may have been rewritten
	! recently; we'll compare %o5 to the current time to verify that it's
	! in the future.  
	!
	! Note that %o5 is live until after 1f.
	! XXX - there is a subroutine call while %o5 is live!
	!
	RD_TICKCMPR(%o5,%g1,%g2,__LINE__)
	srlx	%o5, TICKINT_DIS_SHFT, %g1
	brnz,pt	%g1, 2f
	  nop

	rdpr 	%pstate, %g5
	andn	%g5, PSTATE_IE, %g1
	wrpr	%g0, %g1, %pstate		! Disable vec interrupts

	sethi	%hi(cbe_level14_inum), %o1
	ldx	[%o1 + %lo(cbe_level14_inum)], %o1
	call	intr_enqueue_req ! preserves %o5 and %g5
	  mov	PIL_14, %o0

	! Check SOFTINT for TICKINT/STICKINT
	rd	SOFTINT, %o4
	set	(TICK_INT_MASK | STICK_INT_MASK), %o0
	andcc	%o4, %o0, %g0
	bz,a,pn	%icc, 2f
	  wrpr	%g0, %g5, %pstate		! Enable vec interrupts

	! clear TICKINT/STICKINT
	wr	%o0, CLEAR_SOFTINT

	!
	! Now that we've cleared TICKINT, we can reread %tick and confirm
	! that the value we programmed is still in the future.  If it isn't,
	! we need to reprogram TICK_COMPARE to fire as soon as possible.
	!
	GET_NATIVE_TIME(%o0,%g1,%g2,__LINE__)	! %o0 = tick
	cmp	%o5, %o0			! In the future?
	bg,a,pt	%xcc, 2f			! Yes, drive on.
	  wrpr	%g0, %g5, %pstate		!   delay: enable vec intr

	!
	! If we're here, then we have programmed TICK_COMPARE with a %tick
	! which is in the past; we'll now load an initial step size, and loop
	! until we've managed to program TICK_COMPARE to fire in the future.
	!
	mov	8, %o4				! 8 = arbitrary inital step
1:	add	%o0, %o4, %o5			! Add the step
	WR_TICKCMPR(%o5,%g1,%g2,__LINE__)	! Write to TICK_CMPR
	GET_NATIVE_TIME(%o0,%g1,%g2,__LINE__)	! %o0 = tick
	cmp	%o5, %o0			! In the future?
	bg,a,pt	%xcc, 2f			! Yes, drive on.
	  wrpr	%g0, %g5, %pstate		!    delay: enable vec intr
	ba	1b				! No, try again.
	  sllx	%o4, 1, %o4			!    delay: double step size

2:	ba	current_thread_complete
	  nop
	SET_SIZE(tick_rtt)

#endif /* lint */

#if defined(lint)

/* ARGSUSED */
void
pil15_interrupt(int level)
{}

#else   /* lint */

/*
 * Level-15 interrupt prologue.
 */
       ENTRY_NP(pil15_interrupt)
       CPU_ADDR(%g1, %g2)
       rdpr    %tstate, %g6
       rdpr    %tpc, %g5
       btst    TSTATE_PRIV, %g6                ! trap from supervisor mode?
       bnz,a,pt %xcc, 1f
       stn     %g5, [%g1 + CPU_CPCPROFILE_PC]  ! if so, record kernel PC
       stn     %g5, [%g1 + CPU_CPCPROFILE_UPC] ! if not, record user PC
       ba      pil15_epilogue                  ! must be large-disp branch
       stn     %g0, [%g1 + CPU_CPCPROFILE_PC]  ! zero kernel PC
1:     ba      pil15_epilogue                  ! must be large-disp branch
       stn     %g0, [%g1 + CPU_CPCPROFILE_UPC] ! zero user PC
       SET_SIZE(pil15_interrupt)

#endif  /* lint */

#if defined(lint)
/*
 * Prefetch a page_t for write or read, this assumes a linear
 * scan of sequential page_t's.
 */
/*ARGSUSED*/
void
prefetch_page_w(void *pp)
{}

/*ARGSUSED*/
void
prefetch_page_r(void *pp)
{}
#else	/* lint */

/* XXXQ These should be inline templates, not functions */
        ENTRY(prefetch_page_w)
        retl
	  nop
        SET_SIZE(prefetch_page_w)

        ENTRY(prefetch_page_r)
        retl
	  nop
        SET_SIZE(prefetch_page_r)

#endif	/* lint */

#if defined(lint)
/*
 * Prefetch struct smap for write. 
 */
/*ARGSUSED*/
void
prefetch_smap_w(void *smp)
{}
#else	/* lint */

/* XXXQ These should be inline templates, not functions */
	ENTRY(prefetch_smap_w)
	retl
	  nop
	SET_SIZE(prefetch_smap_w)

#endif	/* lint */

/*
 * Generic sun4v MMU and Cache operations.
 */

#if defined(lint)

/*ARGSUSED*/
void
vtag_flushpage(caddr_t vaddr, uint64_t sfmmup)
{}

/*ARGSUSED*/
void
vtag_flushall(void)
{}

/*ARGSUSED*/
void
vtag_unmap_perm_tl1(uint64_t vaddr, uint64_t ctxnum)
{}

/*ARGSUSED*/
void
vtag_flushpage_tl1(uint64_t vaddr, uint64_t sfmmup)
{}

/*ARGSUSED*/
void
vtag_flush_pgcnt_tl1(uint64_t vaddr, uint64_t sfmmup_pgcnt)
{}

/*ARGSUSED*/
void
vtag_flushall_tl1(uint64_t dummy1, uint64_t dummy2)
{}

/*ARGSUSED*/
void
vac_flushpage(pfn_t pfnum, int vcolor)
{}

/*ARGSUSED*/
void
vac_flushpage_tl1(uint64_t pfnum, uint64_t vcolor)
{}

/*ARGSUSED*/
void
flush_instr_mem(caddr_t vaddr, size_t len)
{}

#else	/* lint */

	ENTRY_NP(vtag_flushpage)
	/*
	 * flush page from the tlb
	 *
	 * %o0 = vaddr
	 * %o1 = sfmmup
	 */
	SFMMU_CPU_CNUM(%o1, %g1, %g2)   /* %g1 = sfmmu cnum on this CPU */

	mov	%g1, %o1 
	mov	MAP_ITLB | MAP_DTLB, %o2
	ta	MMU_UNMAP_ADDR
	brz,pt	%o0, 1f
	  nop
	ba	panic_bad_hcall
	  mov	MMU_UNMAP_ADDR, %o1
1:
 	retl
	  nop
	SET_SIZE(vtag_flushpage)

	ENTRY_NP(vtag_flushall)
	mov	%g0, %o0	! XXX no cpu list yet
	mov	%g0, %o1	! XXX no cpu list yet
	mov	MAP_ITLB | MAP_DTLB, %o2
	mov	MMU_DEMAP_ALL, %o5
	ta	FAST_TRAP
	brz,pt	%o0, 1f
	  nop
	ba	panic_bad_hcall
	  mov	MMU_DEMAP_ALL, %o1
1:
	retl
	  nop
	SET_SIZE(vtag_flushall)

	ENTRY_NP(vtag_unmap_perm_tl1)
	/*
	 * x-trap to unmap perm map entry
	 * %g1 = vaddr
	 * %g2 = ctxnum (KCONTEXT only)
	 */
	mov	%o0, %g3
	mov	%o1, %g4
	mov	%o2, %g5
	mov	%o5, %g6
	mov	%g1, %o0
	mov	%g2, %o1
	mov	MAP_ITLB | MAP_DTLB, %o2
	mov	UNMAP_PERM_ADDR, %o5
	ta	FAST_TRAP
	brz,pt	%o0, 1f
	nop

	mov	PTL1_BAD_HCALL, %g1

	cmp	%o0, H_ENOMAP
	move	%xcc, PTL1_BAD_HCALL_UNMAP_PERM_ENOMAP, %g1
	
	cmp	%o0, H_EINVAL 
	move	%xcc, PTL1_BAD_HCALL_UNMAP_PERM_EINVAL, %g1

	ba,a	ptl1_panic
1:
	mov	%g6, %o5
	mov	%g5, %o2
	mov	%g4, %o1
	mov	%g3, %o0
	retry
	SET_SIZE(vtag_unmap_perm_tl1)

	ENTRY_NP(vtag_flushpage_tl1)
	/*
	 * x-trap to flush page from tlb and tsb
	 *
	 * %g1 = vaddr, zero-extended on 32-bit kernel
	 * %g2 = sfmmup
	 *
	 * assumes TSBE_TAG = 0
	 */
	srln	%g1, MMU_PAGESHIFT, %g1
	slln	%g1, MMU_PAGESHIFT, %g1			/* g1 = vaddr */
	mov	%o0, %g3
	mov	%o1, %g4
	mov	%o2, %g5
	mov	%g1, %o0			/* vaddr */

	SFMMU_CPU_CNUM(%g2, %o1, %g6)   /* %o1 = sfmmu cnum on this CPU */

	mov	MAP_ITLB | MAP_DTLB, %o2
	ta	MMU_UNMAP_ADDR
	brz,pt	%o0, 1f
	nop
	  ba	ptl1_panic
	mov	PTL1_BAD_HCALL, %g1
1:
	mov	%g5, %o2
	mov	%g4, %o1
	mov	%g3, %o0
	membar #Sync
	retry
	SET_SIZE(vtag_flushpage_tl1)

	ENTRY_NP(vtag_flush_pgcnt_tl1)
	/*
	 * x-trap to flush pgcnt MMU_PAGESIZE pages from tlb
	 *
	 * %g1 = vaddr, zero-extended on 32-bit kernel
	 * %g2 = <sfmmup58|pgcnt6>, (pgcnt - 1) is pass'ed in via pgcnt6 bits.
	 *
	 * NOTE: this handler relies on the fact that no
	 *	interrupts or traps can occur during the loop
	 *	issuing the TLB_DEMAP operations. It is assumed
	 *	that interrupts are disabled and this code is
	 *	fetching from the kernel locked text address.
	 *
	 * assumes TSBE_TAG = 0
	 */
	srln	%g1, MMU_PAGESHIFT, %g1
	slln	%g1, MMU_PAGESHIFT, %g1		/* g1 = vaddr */
	mov	%o0, %g3
	mov	%o1, %g4
	mov	%o2, %g5

	and	%g2, SFMMU_PGCNT_MASK, %g7	/* g7 = pgcnt - 1 */
	add	%g7, 1, %g7			/* g7 = pgcnt */

        andn    %g2, SFMMU_PGCNT_MASK, %o0      /* %o0 = sfmmup */

	SFMMU_CPU_CNUM(%o0, %g2, %g6)    /* %g2 = sfmmu cnum on this CPU */

	set	MMU_PAGESIZE, %g6		/* g6 = pgsize */

1:	
	mov	%g1, %o0			/* vaddr */
	mov	%g2, %o1			/* cnum */
	mov	MAP_ITLB | MAP_DTLB, %o2
	ta	MMU_UNMAP_ADDR
	brz,pt	%o0, 2f
	  nop
	ba	ptl1_panic
	  mov	PTL1_BAD_HCALL, %g1
2:
	deccc	%g7				/* decr pgcnt */
	bnz,pt	%icc,1b
	  add	%g1, %g6, %g1			/* go to nextpage */

	mov	%g5, %o2
	mov	%g4, %o1
	mov	%g3, %o0
	membar #Sync
	retry
	SET_SIZE(vtag_flush_pgcnt_tl1)

	! Not implemented on US1/US2
	ENTRY_NP(vtag_flushall_tl1)
	mov	%o0, %g3
	mov	%o1, %g4
	mov	%o2, %g5
	mov	%o3, %g6	! XXXQ not used?
	mov	%o5, %g7
	mov	%g0, %o0	! XXX no cpu list yet
	mov	%g0, %o1	! XXX no cpu list yet
	mov	MAP_ITLB | MAP_DTLB, %o2
	mov	MMU_DEMAP_ALL, %o5
	ta	FAST_TRAP
	brz,pt	%o0, 1f
	  nop
	ba	ptl1_panic
	  mov	PTL1_BAD_HCALL, %g1
1:
	mov	%g7, %o5
	mov	%g6, %o3	! XXXQ not used?
	mov	%g5, %o2
	mov	%g4, %o1
	mov	%g3, %o0
	retry
	SET_SIZE(vtag_flushall_tl1)

/*
 * flush_instr_mem:
 *	Flush a portion of the I-$ starting at vaddr
 * 	%o0 vaddr
 *	%o1 bytes to be flushed
 */

	ENTRY(flush_instr_mem)
	membar	#StoreStore				! Ensure the stores
							! are globally visible
1:
	flush	%o0
	subcc	%o1, ICACHE_FLUSHSZ, %o1		! bytes = bytes-0x20
	bgu,pt	%ncc, 1b
	  add	%o0, ICACHE_FLUSHSZ, %o0		! vaddr = vaddr+0x20

	retl
	  nop
	SET_SIZE(flush_instr_mem)

#endif /* !lint */

#if !defined(CUSTOM_FPZERO)

/*
 * fp_zero() - clear all fp data registers and the fsr
 */

#if defined(lint) || defined(__lint)

void
fp_zero(void)
{}

#else	/* lint */

.global	fp_zero_zero
.align 8
fp_zero_zero:
	.xword	0

	ENTRY_NP(fp_zero)
	sethi	%hi(fp_zero_zero), %o0
	ldx	[%o0 + %lo(fp_zero_zero)], %fsr
	ldd	[%o0 + %lo(fp_zero_zero)], %f0
	fmovd	%f0, %f2
	fmovd	%f0, %f4
	fmovd	%f0, %f6
	fmovd	%f0, %f8
	fmovd	%f0, %f10
	fmovd	%f0, %f12
	fmovd	%f0, %f14
	fmovd	%f0, %f16
	fmovd	%f0, %f18
	fmovd	%f0, %f20
	fmovd	%f0, %f22
	fmovd	%f0, %f24
	fmovd	%f0, %f26
	fmovd	%f0, %f28
	fmovd	%f0, %f30
	fmovd	%f0, %f32
	fmovd	%f0, %f34
	fmovd	%f0, %f36
	fmovd	%f0, %f38
	fmovd	%f0, %f40
	fmovd	%f0, %f42
	fmovd	%f0, %f44
	fmovd	%f0, %f46
	fmovd	%f0, %f48
	fmovd	%f0, %f50
	fmovd	%f0, %f52
	fmovd	%f0, %f54
	fmovd	%f0, %f56
	fmovd	%f0, %f58
	fmovd	%f0, %f60
	retl
	fmovd	%f0, %f62
	SET_SIZE(fp_zero)

#endif	/* lint */
#endif  /* CUSTOM_FPZERO */
