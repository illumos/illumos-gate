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
 * Copyright (c) 1999, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#if !defined(lint)
#include "assym.h"
#endif	/* !lint */

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

/*
 * Override GET_NATIVE_TIME for the cpu module code.  This is not
 * guaranteed to be exactly one instruction, be careful of using
 * the macro in delay slots.
 *
 * Do not use any instruction that modifies condition codes as the 
 * caller may depend on these to remain unchanged across the macro.
 */
#if defined(CHEETAH) || defined(OLYMPUS_C)

#define	GET_NATIVE_TIME(out, scr1, scr2) \
	rd	STICK, out
#define	DELTA_NATIVE_TIME(delta, reg, scr1, scr2, scr3) \
	rd	STICK, reg;		\
	add	reg, delta, reg;	\
	wr	reg, STICK
#define	RD_TICKCMPR(out, scr)		\
	rd	STICK_COMPARE, out
#define	WR_TICKCMPR(in, scr1, scr2, label) \
	wr	in, STICK_COMPARE

#elif defined(HUMMINGBIRD)
#include <sys/spitregs.h>

/*
 * the current hummingbird version of %stick and %stick_cmp
 * were both implemented as (2) 32-bit locations in ASI_IO space;
 * the hdwr should support atomic r/w; meanwhile: ugly alert! ...
 *
 * 64-bit opcodes are required, but move only 32-bits:
 *
 * ldxa [phys]ASI_IO, %dst 	reads  the low 32-bits from phys into %dst
 * stxa %src, [phys]ASI_IO 	writes the low 32-bits from %src into phys
 *
 * reg equivalent		[phys]ASI_IO
 * ------------------		---------------
 * %stick_cmp  low-32		0x1FE.0000.F060
 * %stick_cmp high-32		0x1FE.0000.F068
 * %stick      low-32		0x1FE.0000.F070
 * %stick     high-32		0x1FE.0000.F078
 */
#define	HSTC_LOW	0x60			/* stick_cmp low  32-bits */
#define	HSTC_HIGH	0x68			/* stick_cmp high 32-bits */
#define	HST_LOW		0x70			/* stick low  32-bits */
#define	HST_HIGH	0x78			/* stick high 32-bits */
#define	HST_DIFF	0x08			/* low<-->high diff */

/*
 * Any change in the number of instructions in SETL41()
 * will affect SETL41_OFF
 */
#define	SETL41(reg, byte) \
	sethi	%hi(0x1FE00000), reg;		/* 0000.0000.1FE0.0000 */ \
	or	reg, 0xF, reg;			/* 0000.0000.1FE0.000F */ \
	sllx	reg, 12, reg;			/* 0000.01FE.0000.F000 */ \
	or	reg, byte, reg;			/* 0000.01FE.0000.F0xx */

/*
 * SETL41_OFF is used to calulate the relative PC value when a
 * branch instruction needs to go over SETL41() macro
 */
#define SETL41_OFF  16

/*
 * reading stick requires 2 loads, and there could be an intervening
 * low-to-high 32-bit rollover resulting in a return value that is
 * off by about (2 ^ 32); this rare case is prevented by re-reading
 * the low-32 bits after the high-32 and verifying the "after" value
 * is >= the "before" value; if not, increment the high-32 value.
 *
 * this method is limited to 1 rollover, and based on the fixed
 * stick-frequency (5555555), requires the loads to complete within
 * 773 seconds; incrementing the high-32 value will not overflow for
 * about 52644 years.
 *
 * writing stick requires 2 stores; if the old/new low-32 value is
 * near 0xffffffff, there could be another rollover (also rare).
 * to prevent this, we first write a 0 to the low-32, then write
 * new values to the high-32 then the low-32.
 *
 * When we detect a carry in the lower %stick register, we need to
 * read HST_HIGH again. However at the point where we detect this,
 * we need to rebuild the register address HST_HIGH.This involves more
 * than one instructions and a branch is unavoidable. However, most of
 * the time, there is no carry. So we take the penalty of a branch
 * instruction only when there is carry (less frequent).
 * 
 * For GET_NATIVE_TIME(), we start afresh and branch to SETL41().
 * For DELTA_NATIVE_TIME(), we branch to just after SETL41() since
 * addr already points to HST_LOW.
 *
 * NOTE: this method requires disabling interrupts before using
 * DELTA_NATIVE_TIME.
 */
#define	GET_NATIVE_TIME(out, scr, tmp)	\
	SETL41(scr, HST_LOW);		\
	ldxa	[scr]ASI_IO, tmp;	\
	inc	HST_DIFF, scr;		\
	ldxa	[scr]ASI_IO, out;	\
	dec	HST_DIFF, scr;		\
	ldxa	[scr]ASI_IO, scr;	\
	sub	scr, tmp, tmp;		\
	brlz,pn tmp, .-(SETL41_OFF+24); \
	sllx	out, 32, out;		\
	or	out, scr, out
#define	DELTA_NATIVE_TIME(delta, addr, high, low, tmp) \
	SETL41(addr, HST_LOW);		\
	ldxa	[addr]ASI_IO, tmp;	\
	inc	HST_DIFF, addr;		\
	ldxa	[addr]ASI_IO, high;	\
	dec	HST_DIFF, addr;		\
	ldxa	[addr]ASI_IO, low;	\
	sub	low, tmp, tmp;		\
	brlz,pn tmp, .-24;		\
	sllx	high, 32, high;		\
	or	high, low, high;	\
	add	high, delta, high;	\
	srl	high, 0, low;		\
	srlx	high, 32, high;		\
	stxa	%g0, [addr]ASI_IO;	\
	inc	HST_DIFF, addr;		\
	stxa	high, [addr]ASI_IO;	\
	dec	HST_DIFF, addr;		\
	stxa	low, [addr]ASI_IO
#define RD_TICKCMPR(out, scr)		\
	SETL41(scr, HSTC_LOW);		\
	ldxa	[scr]ASI_IO, out;	\
	inc	HST_DIFF, scr;		\
	ldxa	[scr]ASI_IO, scr;	\
	sllx	scr, 32, scr;		\
	or	scr, out, out
#define WR_TICKCMPR(in, scra, scrd, label) \
	SETL41(scra, HSTC_HIGH);	\
	srlx	in, 32, scrd;		\
	stxa	scrd, [scra]ASI_IO;	\
	dec	HST_DIFF, scra;		\
	stxa	in, [scra]ASI_IO

#else	/* !CHEETAH && !HUMMINGBIRD */

#define	GET_NATIVE_TIME(out, scr1, scr2) \
	rdpr	%tick, out
#define	DELTA_NATIVE_TIME(delta, reg, scr1, scr2, scr3) \
	rdpr	%tick, reg;		\
	add	reg, delta, reg;	\
	wrpr	reg, %tick
#define	RD_TICKCMPR(out, scr)		\
	rd	TICK_COMPARE, out
#ifdef BB_ERRATA_1 /* writes to TICK_COMPARE may fail */
/*
 * Writes to the TICK_COMPARE register sometimes fail on blackbird modules.
 * The failure occurs only when the following instruction decodes to wr or
 * wrpr.  The workaround is to immediately follow writes to TICK_COMPARE
 * with a read, thus stalling the pipe and keeping following instructions
 * from causing data corruption.  Aligning to a quadword will ensure these
 * two instructions are not split due to i$ misses.
 */
#define WR_TICKCMPR(cmpr,scr1,scr2,label)	\
	ba,a	.bb_errata_1.label		;\
	.align	64				;\
.bb_errata_1.label:				;\
	wr	cmpr, TICK_COMPARE		;\
	rd	TICK_COMPARE, %g0
#else	/* BB_ERRATA_1 */
#define	WR_TICKCMPR(in,scr1,scr2,label)		\
	wr	in, TICK_COMPARE
#endif	/* BB_ERRATA_1 */

#endif	/* !CHEETAH && !HUMMINGBIRD */

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
#include <sys/machparam.h>	/* To get SYSBASE and PAGESIZE */
#include <sys/machthread.h>
#include <sys/clock.h>
#include <sys/intreg.h>
#include <sys/psr_compat.h>
#include <sys/isa_defs.h>
#include <sys/dditypes.h>
#include <sys/intr.h>

#if !defined(lint)
#include "assym.h"
#endif	/* !lint */

#if defined(lint)

uint_t
get_impl(void)
{ return (0); }

#else	/* lint */

	ENTRY(get_impl)
	GET_CPU_IMPL(%o0)
	retl
	nop
	SET_SIZE(get_impl)

#endif	/* lint */

#if defined(lint)
/*
 * Softint generated when counter field of tick reg matches value field 
 * of tick_cmpr reg
 */
/*ARGSUSED*/
void
tickcmpr_set(uint64_t clock_cycles)
{}

#else	/* lint */

	ENTRY_NP(tickcmpr_set)
	! get 64-bit clock_cycles interval
	mov	%o0, %o2
	mov	8, %o3			! A reasonable initial step size
1:
	WR_TICKCMPR(%o2,%o4,%o5,__LINE__)	! Write to TICK_CMPR

	GET_NATIVE_TIME(%o0, %o4, %o5)	! Read %tick to confirm the
	sllx	%o0, 1, %o0		!   value we wrote was in the future.
	srlx	%o0, 1, %o0

	cmp	%o2, %o0		! If the value we wrote was in the
	bg,pt	%xcc, 2f		!   future, then blow out of here.
	sllx	%o3, 1, %o3		! If not, then double our step size,
	ba,pt	%xcc, 1b		!   and take another lap.
	add	%o0, %o3, %o2		!
2:
	retl
	nop
	SET_SIZE(tickcmpr_set)

#endif	/* lint */

#if defined(lint)

void
tickcmpr_disable(void)
{}

#else	/* lint */

	ENTRY_NP(tickcmpr_disable)
	mov	1, %g1
	sllx	%g1, TICKINT_DIS_SHFT, %o0
	WR_TICKCMPR(%o0,%o4,%o5,__LINE__)	! Write to TICK_CMPR
	retl
	nop
	SET_SIZE(tickcmpr_disable)

#endif	/* lint */

#if defined(lint)

/*
 * tick_write_delta() increments %tick by the specified delta.  This should
 * only be called after a CPR event to assure that gethrtime() continues to
 * increase monotonically.  Obviously, writing %tick needs to de done very
 * carefully to avoid introducing unnecessary %tick skew across CPUs.  For
 * this reason, we make sure we're i-cache hot before actually writing to
 * %tick.
 */
/*ARGSUSED*/
void
tick_write_delta(uint64_t delta)
{}

#else	/* lint */

#ifdef DEBUG
	.seg	".text"
tick_write_panic:
	.asciz	"tick_write_delta: interrupts already disabled on entry"
#endif	/* DEBUG */

	ENTRY_NP(tick_write_delta)
	rdpr	%pstate, %g1
#ifdef DEBUG
	andcc	%g1, PSTATE_IE, %g0	! If DEBUG, check that interrupts
	bnz	0f			! aren't already disabled.
	sethi	%hi(tick_write_panic), %o1
        save    %sp, -SA(MINFRAME), %sp ! get a new window to preserve caller
	call	panic
	or	%i1, %lo(tick_write_panic), %o0
#endif	/* DEBUG */
0:	wrpr	%g1, PSTATE_IE, %pstate	! Disable interrupts
	mov	%o0, %o2
	ba	0f			! Branch to cache line-aligned instr.
	nop
	.align	16
0:	nop				! The next 3 instructions are now hot.
	DELTA_NATIVE_TIME(%o2, %o3, %o4, %o5, %g2)	! read/inc/write %tick

	retl				! Return
	wrpr	%g0, %g1, %pstate	!     delay: Re-enable interrupts
#endif	/* lint */

#if defined(lint)
/*
 *  return 1 if disabled
 */

int
tickcmpr_disabled(void)
{ return (0); }

#else	/* lint */

	ENTRY_NP(tickcmpr_disabled)
	RD_TICKCMPR(%g1, %o0)
	retl
	srlx	%g1, TICKINT_DIS_SHFT, %o0
	SET_SIZE(tickcmpr_disabled)

#endif	/* lint */

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

#else	/* lint */

	ENTRY(gettick)
	ALTENTRY(randtick)
	GET_NATIVE_TIME(%o0, %o2, %o3)
	retl
	nop
	SET_SIZE(randtick)
	SET_SIZE(gettick)

#endif	/* lint */


/*
 * Return the counter portion of the tick register.
 */

#if defined(lint)

uint64_t
gettick_counter(void)
{ return(0); }

#else	/* lint */

	ENTRY_NP(gettick_counter)
	rdpr	%tick, %o0
	sllx	%o0, 1, %o0
	retl
	srlx	%o0, 1, %o0		! shake off npt bit
	SET_SIZE(gettick_counter)
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
	GET_HRTIME(%g1, %o0, %o1, %o2, %o3, %o4, %o5, %g2)
							! %g1 = hrtime
	retl
	mov	%g1, %o0
	SET_SIZE(gethrtime)

	ENTRY_NP(gethrtime_unscaled)
	GET_NATIVE_TIME(%g1, %o2, %o3)			! %g1 = native time
	retl
	mov	%g1, %o0
	SET_SIZE(gethrtime_unscaled)

	ENTRY_NP(gethrtime_waitfree)
	ALTENTRY(dtrace_gethrtime)
	GET_NATIVE_TIME(%g1, %o2, %o3)			! %g1 = native time
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
	GET_HRTIME(%g1, %g2, %g3, %g4, %g5, %o0, %o1, %o2)	! %g1 = hrtime
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
	sub	hrestnsec, nano, hrestnsec; /* hrest.tv_nsec -= NANOSEC; */ \
	ba,a	3b;			/* check >= billion again */	\
4:

	ENTRY_NP(gethrestime)
	GET_HRESTIME(%o1, %o2, %o3, %o4, %o5, %g1, %g2, %g3, %g4)
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
	GET_HRESTIME(%o0, %o2, %o3, %o4, %o5, %g1, %g2, %g3, %g4)
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
	GET_HRESTIME(%o0, %o1, %g1, %g2, %g3, %g4, %g5, %o2, %o3)
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
	GET_NATIVE_TIME(%g5, %g1, %g2)	! %g5 = native time in ticks
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
	GET_NATIVE_TIME(%l0, %l3, %l6)		! current native time
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
	GET_NATIVE_TIME(%g1, %g2, %g3)
	KSTAT_Q_UPDATE(add, BRZPT, 1f, 1:retl, KSTAT_IO_W)
	SET_SIZE(kstat_waitq_enter)

	.align 16
	ENTRY(kstat_waitq_exit)
	GET_NATIVE_TIME(%g1, %g2, %g3)
#if defined(DEBUG)
	KSTAT_Q_UPDATE(sub, BRZPN, kstat_q_panic, retl, KSTAT_IO_W)
#else
	KSTAT_Q_UPDATE_ND(sub, retl, KSTAT_IO_W)
#endif
	SET_SIZE(kstat_waitq_exit)

	.align 16
	ENTRY(kstat_runq_enter)
	GET_NATIVE_TIME(%g1, %g2, %g3)
	KSTAT_Q_UPDATE(add, BRZPT, 1f, 1:retl, KSTAT_IO_R)
	SET_SIZE(kstat_runq_enter)

	.align 16
	ENTRY(kstat_runq_exit)
	GET_NATIVE_TIME(%g1, %g2, %g3)
#if defined(DEBUG)
	KSTAT_Q_UPDATE(sub, BRZPN, kstat_q_panic, retl, KSTAT_IO_R)
#else
	KSTAT_Q_UPDATE_ND(sub, retl, KSTAT_IO_R)
#endif
	SET_SIZE(kstat_runq_exit)

	.align 16
	ENTRY(kstat_waitq_to_runq)
	GET_NATIVE_TIME(%g1, %g2, %g3)
#if defined(DEBUG)
	KSTAT_Q_UPDATE(sub, BRZPN, kstat_q_panic, 1:, KSTAT_IO_W)
#else
	KSTAT_Q_UPDATE_ND(sub, 1:, KSTAT_IO_W)
#endif
	KSTAT_Q_UPDATE(add, BRZPT, 1f, 1:retl, KSTAT_IO_R)
	SET_SIZE(kstat_waitq_to_runq)

	.align 16
	ENTRY(kstat_runq_back_to_waitq)
	GET_NATIVE_TIME(%g1, %g2, %g3)
#if defined(DEBUG)
	KSTAT_Q_UPDATE(sub, BRZPN, kstat_q_panic, 1:, KSTAT_IO_R)
#else
	KSTAT_Q_UPDATE_ND(sub, 1:, KSTAT_IO_R)
#endif
	KSTAT_Q_UPDATE(add, BRZPT, 1f, 1:retl, KSTAT_IO_W)
	SET_SIZE(kstat_runq_back_to_waitq)

#endif	/* !(lint || __lint) */

#ifdef lint	

int64_t timedelta;
hrtime_t hres_last_tick;
volatile timestruc_t hrestime;
int64_t hrestime_adj;
volatile int hres_lock;
uint_t nsec_scale;
hrtime_t hrtime_base;
int traptrace_use_stick;

#else	/* lint */
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
	.global	nsec_shift, adj_shift

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

#endif	/* lint */


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
 *
 * For OPL platforms that support the "sleep" instruction, we
 * conditionally (ifdef'ed) insert a "sleep" instruction in
 * the loop. Note that theoritically we should have move (duplicated)
 * the code down to spitfire/us3/opl specific asm files - but this
 * is alot of code duplication just to add one "sleep" instruction.
 * We chose less code duplication for this.
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
	GET_NATIVE_TIME(%o2, %o3, %o4)
	add	%o1, %o2, %o1

1:
#ifdef	_OPL
	.word 0x81b01060		! insert "sleep" instruction
#endif /* _OPL */			! use byte code for now
	cmp	%o1, %o2
	GET_NATIVE_TIME(%o2, %o3, %o4)
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

#else	/* lint */

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
	RD_TICKCMPR(%o5, %g1)
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
	GET_NATIVE_TIME(%o0, %g1, %g2)		! %o0 = tick
	sllx	%o0, 1, %o0			! Clear the DIS bit
	srlx	%o0, 1, %o0
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
	GET_NATIVE_TIME(%o0, %g1, %g2)		! %o0 = tick
	sllx	%o0, 1, %o0			! Clear the DIS bit
	srlx	%o0, 1, %o0
	cmp	%o5, %o0			! In the future?
	bg,a,pt	%xcc, 2f			! Yes, drive on.
	wrpr	%g0, %g5, %pstate		!    delay: enable vec intr
	ba	1b				! No, try again.
	sllx	%o4, 1, %o4			!    delay: double step size

2:	ba	current_thread_complete
	nop
	SET_SIZE(tick_rtt)

#endif	/* lint */

#if defined(lint)

/* ARGSUSED */
void
pil15_interrupt(int level)
{}

#else  /* lint */

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

#endif /* lint */

#if defined(lint) || defined(__lint)

/* ARGSUSED */
uint64_t
find_cpufrequency(volatile uchar_t *clock_ptr)
{
	return (0);
}

#else	/* lint */

#ifdef DEBUG
	.seg	".text"
find_cpufreq_panic:
	.asciz	"find_cpufrequency: interrupts already disabled on entry"
#endif	/* DEBUG */

	ENTRY_NP(find_cpufrequency)
	rdpr	%pstate, %g1

#ifdef DEBUG
	andcc	%g1, PSTATE_IE, %g0	! If DEBUG, check that interrupts
	bnz	0f			! are currently enabled
	sethi	%hi(find_cpufreq_panic), %o1
	call	panic
	or	%o1, %lo(find_cpufreq_panic), %o0
#endif	/* DEBUG */

0:
	wrpr	%g1, PSTATE_IE, %pstate	! Disable interrupts
3:
	ldub	[%o0], %o1		! Read the number of seconds
	mov	%o1, %o2		! remember initial value in %o2
1:
	GET_NATIVE_TIME(%o3, %g4, %g5)
	cmp	%o1, %o2		! did the seconds register roll over?
	be,pt	%icc, 1b		! branch back if unchanged
	ldub	[%o0], %o2		!   delay: load the new seconds val

	brz,pn	%o2, 3b			! if the minutes just rolled over,
					! the last second could have been
					! inaccurate; try again.
	mov	%o2, %o4		!   delay: store init. val. in %o2
2:
	GET_NATIVE_TIME(%o5, %g4, %g5)
	cmp	%o2, %o4		! did the seconds register roll over?
	be,pt	%icc, 2b		! branch back if unchanged
	ldub	[%o0], %o4		!   delay: load the new seconds val

	brz,pn	%o4, 0b			! if the minutes just rolled over,
					! the last second could have been
					! inaccurate; try again.
	wrpr	%g0, %g1, %pstate	!   delay: re-enable interrupts

	retl
	sub	%o5, %o3, %o0		! return the difference in ticks
	SET_SIZE(find_cpufrequency)

#endif	/* lint */

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

#if defined(CHEETAH) || defined(CHEETAH_PLUS) || defined(JALAPENO) || \
	defined(SERRANO)
	!
	! On US-III, the prefetch instruction queue is 8 entries deep.
	! Also, prefetches for write put data in the E$, which has
	! lines of 512 bytes for an 8MB cache. Each E$ line is further
	! subblocked into 64 byte chunks.
	!
	! Since prefetch can only bring in 64 bytes at a time (See Sparc
	! v9 Architecture Manual pp.204) and a page_t is 128 bytes,
	! then 2 prefetches are required in order to bring an entire
	! page into the E$.
	!
	! Since the prefetch queue is 8 entries deep, we currently can
	! only have 4 prefetches for page_t's outstanding. Thus, we
	! prefetch n+4 ahead of where we are now: 
	!
	!      4 * sizeof(page_t)     -> 512
	!      4 * sizeof(page_t) +64 -> 576
	! 
	! Example
	! =======
	! contiguous page array in memory...
	!
	! |AAA1|AAA2|BBB1|BBB2|CCC1|CCC2|DDD1|DDD2|XXX1|XXX2|YYY1|YYY2|...
	! ^         ^         ^         ^         ^    ^
	! pp                                      |    pp+4*sizeof(page)+64
	!                                         |
	!                                         pp+4*sizeof(page)
	!
	!  Prefetch
	!   Queue
	! +-------+<--- In this iteration, we're working with pp (AAA1),
	! |Preftch|     but we enqueue prefetch for addr = XXX1
	! | XXX1  | 
	! +-------+<--- this queue slot will be a prefetch instruction for
	! |Preftch|     for addr = pp + 4*sizeof(page_t) + 64 (or second
	! | XXX2  |     half of page XXX)
	! +-------+ 
	! |Preftch|<-+- The next time around this function, we'll be
	! | YYY1  |  |  working with pp = BBB1, but will be enqueueing
	! +-------+  |  prefetches to for both halves of page YYY,
	! |Preftch|  |  while both halves of page XXX are in transit
	! | YYY2  |<-+  make their way into the E$.
	! +-------+
	! |Preftch|
	! | ZZZ1  |
	! +-------+
	! .       .
	! :       :
	!
	!  E$
	! +============================================...
	! | XXX1 | XXX2 | YYY1 | YYY2 | ZZZ1 | ZZZ2 |
	! +============================================...
	! |      |      |      |      |      |      |
	! +============================================...
	! .
	! :
	!
	! So we should expect the first four page accesses to stall
	! while we warm up the cache, afterwhich, most of the pages
	! will have their pp ready in the E$.
	! 
	! Also note that if sizeof(page_t) grows beyond 128, then 
	! we'll need an additional prefetch to get an entire page
	! into the E$, thus reducing the number of outstanding page
	! prefetches to 2 (ie. 3 prefetches/page = 6 queue slots)
	! etc.
	!
	! Cheetah+
	! ========
	! On Cheetah+ we use "#n_write" prefetches as these avoid
	! unnecessary RTS->RTO bus transaction state change, and
	! just issues RTO transaction. (See pp.77 of Cheetah+ Delta
	! PRM). On Cheetah, #n_write prefetches are reflected with
	! RTS->RTO state transition regardless.
	!
#define STRIDE1 512
#define STRIDE2 576

#if	STRIDE1 != (PAGE_SIZE * 4)
#error	"STRIDE1 != (PAGE_SIZE * 4)"
#endif	/* STRIDE1 != (PAGE_SIZE * 4) */

        ENTRY(prefetch_page_w)
        prefetch        [%o0+STRIDE1], #n_writes
        retl
        prefetch        [%o0+STRIDE2], #n_writes
        SET_SIZE(prefetch_page_w)

	!
	! Note on CHEETAH to prefetch for read, we really use #one_write.
	! This fetches to E$ (general use) rather than P$ (floating point use).
	!
        ENTRY(prefetch_page_r)
        prefetch        [%o0+STRIDE1], #one_write
        retl
        prefetch        [%o0+STRIDE2], #one_write
        SET_SIZE(prefetch_page_r)

#elif defined(SPITFIRE) || defined(HUMMINGBIRD)

	!
	! UltraSparcII can have up to 3 prefetches outstanding.
	! A page_t is 128 bytes (2 prefetches of 64 bytes each)
	! So prefetch for pp + 1, which is
	!
	!       pp + sizeof(page_t)
	! and
	!       pp + sizeof(page_t) + 64
	!
#define STRIDE1	128
#define STRIDE2	192

#if	STRIDE1 != PAGE_SIZE
#error	"STRIDE1 != PAGE_SIZE"
#endif	/* STRIDE1 != PAGE_SIZE */

        ENTRY(prefetch_page_w)
        prefetch        [%o0+STRIDE1], #n_writes
        retl
        prefetch        [%o0+STRIDE2], #n_writes
        SET_SIZE(prefetch_page_w)

        ENTRY(prefetch_page_r)
        prefetch        [%o0+STRIDE1], #n_reads
        retl
        prefetch        [%o0+STRIDE2], #n_reads
        SET_SIZE(prefetch_page_r)

#elif defined(OLYMPUS_C)
	!
	! Prefetch strides for Olympus-C
	!

#define STRIDE1	0x440
#define STRIDE2	0x640
	
	ENTRY(prefetch_page_w)
        prefetch        [%o0+STRIDE1], #n_writes
	retl
        prefetch        [%o0+STRIDE2], #n_writes
	SET_SIZE(prefetch_page_w)

	ENTRY(prefetch_page_r)
        prefetch        [%o0+STRIDE1], #n_writes
	retl
        prefetch        [%o0+STRIDE2], #n_writes
	SET_SIZE(prefetch_page_r)
#else	/* OLYMPUS_C */

#error "You need to fix this for your new cpu type."

#endif	/* OLYMPUS_C */

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

#if defined(CHEETAH) || defined(CHEETAH_PLUS) || defined(JALAPENO) || \
	defined(SERRANO)

#define	PREFETCH_Q_LEN 8

#elif defined(SPITFIRE) || defined(HUMMINGBIRD)

#define	PREFETCH_Q_LEN 3

#elif defined(OLYMPUS_C)
	!
	! Use length of one for now.
	!
#define	PREFETCH_Q_LEN	1

#else 	/* OLYMPUS_C */

#error You need to fix this for your new cpu type.

#endif	/* OLYMPUS_C */

#include <vm/kpm.h>

#ifdef	SEGKPM_SUPPORT

#define	SMAP_SIZE 72
#define SMAP_STRIDE (((PREFETCH_Q_LEN * 64) / SMAP_SIZE) * 64)

#else	/* SEGKPM_SUPPORT */

	!
	! The hardware will prefetch the 64 byte cache aligned block
	! that contains the address specified in the prefetch instruction.
	! Since the size of the smap struct is 48 bytes, issuing 1 prefetch
	! per pass will suffice as long as we prefetch far enough ahead to
	! make sure we don't stall for the cases where the smap object
	! spans multiple hardware prefetch blocks.  Let's prefetch as far
	! ahead as the hardware will allow.
	!
	! The smap array is processed with decreasing address pointers.
	!
#define	SMAP_SIZE 48
#define	SMAP_STRIDE (PREFETCH_Q_LEN * SMAP_SIZE)

#endif	/* SEGKPM_SUPPORT */

	ENTRY(prefetch_smap_w)
	retl
	prefetch	[%o0-SMAP_STRIDE], #n_writes
	SET_SIZE(prefetch_smap_w)

#endif	/* lint */

#if defined(lint) || defined(__lint)

/* ARGSUSED */
uint64_t
getidsr(void)
{ return 0; }

#else	/* lint */

	ENTRY_NP(getidsr)
	retl
	ldxa	[%g0]ASI_INTR_DISPATCH_STATUS, %o0
	SET_SIZE(getidsr)

#endif	/* lint */
