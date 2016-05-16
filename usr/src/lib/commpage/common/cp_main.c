/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2016 Joyent, Inc.
 */


#include <sys/comm_page.h>
#include <sys/tsc.h>

/*
 * ASM-defined functions.
 */
extern hrtime_t __cp_tsc_read(uint_t);
extern hrtime_t __cp_tsc_readcpu(uint_t, uint_t *);
extern uint_t __cp_do_getcpu(uint_t);

/*
 * These are cloned from TSC and time related code in the kernel.  The should
 * be kept in sync in the case that the source values are changed.
 */
#define	NSEC_SHIFT	5
#define	ADJ_SHIFT	4
#define	NANOSEC		1000000000LL

#define	TSC_CONVERT_AND_ADD(tsc, hrt, scale) do {		\
	uint32_t *_l = (uint32_t *)&(tsc); 			\
	uint64_t sc = (uint32_t)(scale);			\
	(hrt) += (uint64_t)(_l[1] * sc) << NSEC_SHIFT;		\
	(hrt) += (uint64_t)(_l[0] * sc) >> (32 - NSEC_SHIFT);	\
} while (0)


/*
 * Userspace version of tsc_gethrtime.
 * See: uts/i86pc/os/timestamp.c
 */
hrtime_t
__cp_gethrtime(comm_page_t *cp)
{
	uint32_t old_hres_lock;
	hrtime_t tsc, hrt, tsc_last;

	/*
	 * Several precautions must be taken when collecting the data necessary
	 * to perform an accurate gethrtime calculation.
	 *
	 * While much of the TSC state stored in the comm page is unchanging
	 * after boot, portions of it are periodically updated during OS ticks.
	 * Changes to hres_lock during the course of the copy indicates a
	 * potentially inconsistent snapshot, necessitating a loop.
	 *
	 * Even more complicated is the handling for TSCs which require sync
	 * offsets between different CPUs.  Since userspace lacks the luxury of
	 * disabling interrupts, a validation loop checking for CPU migrations
	 * is used.  Pathological scheduling could, in theory, "outwit"
	 * this check.  Such a possibility is considered an acceptable risk.
	 *
	 */
	if (cp->cp_tsc_ncpu == 0) {
		/*
		 * No per-CPU offset data, use the simple hres_lock loop.
		 */
		do {
			old_hres_lock = cp->cp_hres_lock;
			tsc_last = cp->cp_tsc_last;
			hrt = cp->cp_tsc_hrtime_base;
			tsc = __cp_tsc_read(cp->cp_tsc_type);
		} while ((old_hres_lock & ~1) != cp->cp_hres_lock);
	} else {
		/*
		 * Per-CPU offset data is needed for an accurate TSC reading.
		 */
		do {
			uint_t cpu_id;

			old_hres_lock = cp->cp_hres_lock;
			tsc_last = cp->cp_tsc_last;
			hrt = cp->cp_tsc_hrtime_base;
			/*
			 * When collecting the TSC and cpu_id, cp_tsc_readcpu
			 * will accurately detect CPU migrations in all but
			 * the most pathological scheduling conditions.
			 */
			tsc = __cp_tsc_readcpu(cp->cp_tsc_type, &cpu_id);
			tsc += cp->cp_tsc_sync_tick_delta[cpu_id];
		} while ((old_hres_lock & ~1) != cp->cp_hres_lock);
	}

	if (tsc >= tsc_last) {
		tsc -= tsc_last;
	} else if (tsc >= tsc_last - (2 * cp->cp_tsc_max_delta)) {
		tsc = 0;
	} else if (tsc > cp->cp_tsc_resume_cap) {
		tsc = cp->cp_tsc_resume_cap;
	}
	TSC_CONVERT_AND_ADD(tsc, hrt, cp->cp_nsec_scale);

	return (hrt);
}

/*
 * Userspace version of pc_gethrestime.
 * See: uts/i86pc/os/machdep.c
 */
void
__cp_clock_gettime_realtime(comm_page_t *cp, timespec_t *tp)
{
	int lock_prev, nslt, adj;
	timespec_t now;
	int64_t hres_adj;

loop:
	lock_prev = cp->cp_hres_lock;
	now.tv_sec = cp->cp_hrestime[0];
	now.tv_nsec = cp->cp_hrestime[1];
	nslt = (int)(__cp_gethrtime(cp) - cp->cp_hres_last_tick);
	hres_adj = cp->cp_hrestime_adj;
	if (nslt < 0) {
		/*
		 * Tick came between sampling hrtime and hres_last_tick;
		 */
		goto loop;
	}
	now.tv_nsec += nslt;
	if (hres_adj != 0) {
		if (hres_adj > 0) {
			adj = (nslt >> ADJ_SHIFT);
			if (adj > hres_adj)
				adj = (int)hres_adj;
		} else {
			adj = -(nslt >> ADJ_SHIFT);
			if (adj < hres_adj)
				adj = (int)hres_adj;
		}
		now.tv_nsec += adj;
	}
	while ((unsigned long)now.tv_nsec >= NANOSEC) {
		/*
		 * Rope in tv_nsec from any excessive adjustments.
		 */
		now.tv_nsec -= NANOSEC;
		now.tv_sec++;
	}
	if ((cp->cp_hres_lock & ~1) != lock_prev)
		goto loop;

	*tp = now;
}

/*
 * Interrogate if querying the clock via the comm page is possible.
 */
int
__cp_can_gettime(comm_page_t *cp)
{
	switch (cp->cp_tsc_type) {
	case TSC_TSCP:
	case TSC_RDTSC_MFENCE:
	case TSC_RDTSC_LFENCE:
	case TSC_RDTSC_CPUID:
		return (0);
	default:
		break;
	}
	return (1);
}

/*
 * Query which CPU this LWP is running on.
 */
uint_t
__cp_getcpu(comm_page_t *cp)
{
	return (__cp_do_getcpu(cp->cp_tsc_type));
}
