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

#ifndef _SYS_CLOCK_H
#define	_SYS_CLOCK_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/spl.h>
#include <sys/time.h>
#include <sys/machclock.h>

#ifndef _ASM

#ifdef	_KERNEL

extern void	setcpudelay(void);

extern uint_t	nsec_scale;
extern uint_t	nsec_shift;
extern uint_t	nsec_per_sys_tick;
extern uint64_t	sys_tick_freq;

extern int	traptrace_use_stick;
extern uint64_t	system_clock_freq;
extern uint_t	sys_clock_mhz;

extern void mon_clock_init(void);
extern void mon_clock_start(void);
extern void mon_clock_stop(void);
extern void mon_clock_share(void);
extern void mon_clock_unshare(void);

extern hrtime_t hrtime_base;
extern void hres_tick(void);
extern void	clkstart(void);
extern void cbe_level14();
extern hrtime_t tick2ns(hrtime_t, uint_t);

typedef struct {
	uint64_t cbe_level1_inum;
	uint64_t cbe_level10_inum;
} cbe_data_t;

#endif	/* _KERNEL */

#endif	/* _ASM */


#define	CBE_LOW_PIL	1
#define	CBE_LOCK_PIL	LOCK_LEVEL
#define	CBE_HIGH_PIL	14

#define	ADJ_SHIFT	4	/* used in get_hrestime and _level10 */

/*
 * Locking strategy for high-resolution timing services
 *
 * We generally construct timestamps from two or more components:
 * a hardware time source and one or more software time sources.
 * These components cannot all be loaded simultaneously, so we need
 * some sort of locking strategy to generate consistent timestamps.
 *
 * To minimize lock contention and cache thrashing we employ the
 * weakest possible synchronization model: writers (rare) serialize
 * on an acquisition-counting mutex, described below; readers (common)
 * execute in parallel with no synchronization at all -- they don't
 * exclude other readers, and they don't even exclude writers.  Instead,
 * readers just examine the writer lock's value before and after loading
 * all the components of a timestamp to detect writer intervention.
 * In the rare case when a writer does intervene, the reader will
 * detect it, discard the timestamp and try again.
 *
 * The writer lock, hres_lock, is a 32-bit integer consisting of an
 * 8-bit lock and a 24-bit acquisition count.  To acquire the lock we
 * set the lock field with ldstub, which sets the low-order 8 bits to
 * 0xff; to clear the lock, we increment it, which simultaneously clears
 * the lock field (0xff --> 0x00) and increments the acquisition count
 * (due to carry into bit 8).  Thus each acquisition transforms hres_lock
 * from N:0 to N:ff, and each release transforms N:ff into (N+1):0.
 *
 * Readers can detect writer intervention by loading hres_lock before
 * and after loading the time components they need; if either lock value
 * contains 0xff in the low-order bits (lock held), or if the lock values
 * are not equal (lock was acquired and released), a writer intervened
 * and the reader must try again.  If the lock values are equal and the
 * low-order 8 bits are clear, the timestamp must be valid.  We can check
 * both of these conditions with a single compare instruction by checking
 * whether old_hres_lock & ~1 == new_hres_lock, as illustrated by the
 * following table of all possible lock states:
 *
 *	initial	& ~1	final		result of compare
 *	------------	-----		-----------------
 *	now:00		now:00		valid
 *	now:00		now:ff		invalid
 *	now:00		later:00	invalid
 *	now:00		later:ff	invalid
 *	now:fe		now:ff		invalid
 *	now:fe		later:00	invalid
 *	now:fe		later:ff	invalid
 *
 * Implementation considerations:
 *
 * (1) Load buffering.
 *
 * On a CPU that does load buffering we must ensure that the load of
 * hres_lock completes before the load of any timestamp components.
 * This is essential *even on a CPU that does in-order loads* because
 * accessing the hardware time source may not involve a memory reference
 * (e.g. rd %tick).  A convenient way to address this is to clear the
 * lower bit (andn with 1) of the old lock value right away, since this
 * generates a dependency on the load of hres_lock.  We have to do this
 * anyway to perform the lock comparison described above.
 *
 * (2) Out-of-order loads.
 *
 * On a CPU that does out-of-order loads we must ensure that the loads
 * of all timestamp components have completed before we load the final
 * value of hres_lock.  This can be done either by generating load
 * dependencies on the timestamp components or by membar #LoadLoad.
 *
 * (3) Interaction with the high level cyclic handler, hres_tick().
 *
 * One unusual property of hres_lock is that it's acquired in a high
 * level cyclic handler, hres_tick().  Thus, hres_lock must be acquired at
 * CBE_HIGH_PIL or higher to prevent single-CPU deadlock.
 *
 * (4) Cross-calls.
 *
 * If a cross-call happens while one CPU has hres_lock and another is
 * trying to acquire it in the clock interrupt path, the system will
 * deadlock: the first CPU will never release hres_lock since it's
 * waiting to be released from the cross-call, and the cross-call can't
 * complete because the second CPU is spinning on hres_lock with traps
 * disabled.  Thus cross-calls must be blocked while holding hres_lock.
 *
 * Together, (3) and (4) imply that hres_lock should only be acquired
 * at PIL >= max(XCALL_PIL, CBE_HIGH_PIL), or while traps are disabled.
 */
#define	HRES_LOCK_OFFSET 3

#define	CLOCK_LOCK(oldsplp)	\
	lock_set_spl((lock_t *)&hres_lock + HRES_LOCK_OFFSET, \
		ipltospl(CBE_HIGH_PIL), oldsplp)

#define	CLOCK_UNLOCK(spl)	\
	membar_ldst_stst();	\
	hres_lock++;		\
	splx(spl);		\
	LOCKSTAT_RECORD0(LS_CLOCK_UNLOCK_RELEASE,	\
		(lock_t *)&hres_lock + HRES_LOCK_OFFSET);

/*
 * NATIVE_TIME_TO_NSEC_SCALE is called with NSEC_SHIFT to convert hi-res
 * timestamps into nanoseconds. On systems that have a %stick register,
 * hi-res timestamps are in %stick units. On systems that do not have a
 * %stick register, hi-res timestamps are in %tick units.
 *
 * NATIVE_TIME_TO_NSEC_SCALE is called with TICK_NSEC_SHIFT to convert from
 * %tick units to nanoseconds on all implementations whether %stick is
 * available or not.
 */

/*
 * At least 62.5 MHz CPU %tick frequency
 */

#define	TICK_NSEC_SHIFT	4

/*
 * Convert hi-res native time (V9's %tick in our case) into nanoseconds.
 *
 * The challenge is to multiply a %tick value by (NANOSEC / sys_tick_freq)
 * without using floating point and without overflowing 64-bit integers.
 * We assume that all sun4u systems will have a 16 nsec or better clock
 * (i.e. faster than 62.5 MHz), which means that (ticks << 4) has units
 * greater than one nanosecond, so converting from (ticks << 4) to nsec
 * requires multiplication by a rational number, R, between 0 and 1.
 * To avoid floating-point we precompute (R * 2^32) during boot and
 * stash this away in nsec_scale.  Thus we can compute (tick * R) as
 * (tick * nsec_scale) >> 32, which is accurate to about 1 part per billion.
 *
 * To avoid 64-bit overflow when multiplying (tick << 4) by nsec_scale,
 * we split (tick << 4) into its high and low 32-bit pieces, H and L,
 * multiply each piece separately, and add up the relevant bits of the
 * partial products.  Putting it all together we have:
 *
 * nsec = (tick << 4) * R
 *	= ((tick << 4) * nsec_scale) >> 32
 *	= ((H << 32) + L) * nsec_scale) >> 32
 *	= (H * nsec_scale) + ((L * nsec_scale) >> 32)
 *
 * The last line is the computation we actually perform: it requires no
 * floating point and all intermediate results fit in 64-bit registers.
 *
 * Note that we require that tick is less than (1 << (64 - NSEC_SHIFT));
 * greater values will result in overflow and misbehavior (not that this
 * is a serious problem; (1 << (64 - NSEC_SHIFT)) nanoseconds is over
 * thirty-six years).  Nonetheless, clients may wish to be aware of this
 * limitation; NATIVE_TIME_MAX() returns this maximum native time.
 *
 * We provide two versions of this macro: a "full-service" version that
 * just converts ticks to nanoseconds and a higher-performance version that
 * expects the scaling factor nsec_scale as its second argument (so that
 * callers can distance the load of nsec_scale from its use).  Note that
 * we take a fast path if we determine the ticks to be less than 32 bits
 * (as it often is for the delta between %tick values for successive
 * firings of the hres_tick() cyclic).
 *
 * Note that in the 32-bit path we don't even bother clearing NPT.
 * We get away with this by making hardclk.c ensure than nsec_scale
 * is even, so we can take advantage of the associativity of modular
 * arithmetic: multiplying %tick by any even number, say 2*n, is
 * equivalent to multiplying %tick by 2, then by n.  Multiplication
 * by 2 is equivalent to shifting left by one, which clears NPT.
 *
 * Finally, note that the macros use the labels "6:" and "7:"; these
 * labels must not be used across an invocation of either macro.
 */
#define	NATIVE_TIME_TO_NSEC_SCALE(out, scr1, scr2, shift)		\
	srlx	out, 32, scr2;		/* check high 32 bits */	\
/* CSTYLED */ 								\
	brz,a,pt scr2, 6f;		/* if clear, 32-bit fast path */\
	mulx	out, scr1, out;		/* delay: 32-bit fast path */	\
	sllx	out, shift, out;	/* clear NPT and pre-scale */	\
	srlx	out, 32, scr2;		/* scr2 = hi32(tick<<4) = H */	\
	mulx	scr2, scr1, scr2;	/* scr2 = (H*F) */		\
	srl	out, 0, out;		/* out = lo32(tick<<4) = L */	\
	mulx	out, scr1, scr1;	/* scr1 = (L*F) */		\
	srlx	scr1, 32, scr1;		/* scr1 = (L*F) >> 32 */	\
	ba	7f;			/* branch over 32-bit path */	\
	add	scr1, scr2, out;	/* out = (H*F) + ((L*F) >> 32) */\
6:									\
	srlx	out, 32 - shift, out;					\
7:

#define	NATIVE_TIME_TO_NSEC(out, scr1, scr2)				\
	sethi	%hi(nsec_scale), scr1;	/* load scaling factor */	\
	ld	[scr1 + %lo(nsec_scale)], scr1;				\
	NATIVE_TIME_TO_NSEC_SCALE(out, scr1, scr2, NSEC_SHIFT);

#define	NATIVE_TIME_MAX(out)						\
	mov	-1, out;						\
	srlx	out, NSEC_SHIFT, out

/*
 * NSEC_SHIFT and VTRACE_SHIFT constants are defined in
 * <sys/machclock.h> file.
 */

#ifdef	__cplusplus
}
#endif

#endif	/* !_SYS_CLOCK_H */
