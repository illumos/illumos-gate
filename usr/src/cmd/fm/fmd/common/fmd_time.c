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

#include <sys/fm/protocol.h>
#include <signal.h>
#include <limits.h>
#include <time.h>

#include <fmd_time.h>
#include <fmd_alloc.h>
#include <fmd_error.h>
#include <fmd_subr.h>
#include <fmd.h>

void
fmd_time_gettimeofday(struct timeval *tvp)
{
	if (fmd.d_clockops->fto_gettimeofday(tvp, NULL) != 0)
		fmd_panic("failed to read time-of-day clock");
}

hrtime_t
fmd_time_gethrtime(void)
{
	return (fmd.d_clockops->fto_gethrtime());
}

void
fmd_time_addhrtime(hrtime_t delta)
{
	fmd.d_clockops->fto_addhrtime(delta);
}

void
fmd_time_waithrtime(hrtime_t delta)
{
	fmd.d_clockops->fto_waithrtime(delta);
}

void
fmd_time_waitcancel(pthread_t tid)
{
	fmd.d_clockops->fto_waitcancel(tid);
}

/*
 * To synchronize TOD with a gethrtime() source, we repeatedly sample TOD in
 * between two calls to gethrtime(), which places a reasonably tight bound on
 * the high-resolution time that matches the TOD value we sampled.  We repeat
 * this process several times and ultimately select the sample where the two
 * values of gethrtime() were closest.  We then assign the average of those
 * two high-resolution times to be the gethrtime() associated with that TOD.
 */
void
fmd_time_sync(fmd_timeval_t *ftv, hrtime_t *hrp, uint_t samples)
{
	const fmd_timeops_t *ftop = fmd.d_clockops;
	hrtime_t hrtbase, hrtmin = INT64_MAX;
	struct timeval todbase;
	uint_t i;

	for (i = 0; i < samples; i++) {
		hrtime_t t0, t1, delta;
		struct timeval tod;

		t0 = ftop->fto_gethrtime();
		(void) ftop->fto_gettimeofday(&tod, NULL);
		t1 = ftop->fto_gethrtime();
		delta = t1 - t0;

		if (delta < hrtmin) {
			hrtmin = delta;
			hrtbase = t0 + delta / 2;
			todbase = tod;
		}
	}

	if (ftv != NULL) {
		ftv->ftv_sec = todbase.tv_sec;
		ftv->ftv_nsec = todbase.tv_usec * (NANOSEC / MICROSEC);
	}

	if (hrp != NULL)
		*hrp = hrtbase;
}

/*
 * Convert a high-resolution timestamp into 64-bit seconds and nanoseconds.
 * For efficiency, the multiplication and division are expanded using the
 * clever algorithm originally designed for the kernel in hrt2ts().  Refer to
 * the comments in uts/common/os/timers.c for an explanation of how it works.
 */
static void
fmd_time_hrt2ftv(hrtime_t hrt, fmd_timeval_t *ftv)
{
	uint32_t sec, nsec, tmp;

	tmp = (uint32_t)(hrt >> 30);
	sec = tmp - (tmp >> 2);
	sec = tmp - (sec >> 5);
	sec = tmp + (sec >> 1);
	sec = tmp - (sec >> 6) + 7;
	sec = tmp - (sec >> 3);
	sec = tmp + (sec >> 1);
	sec = tmp + (sec >> 3);
	sec = tmp + (sec >> 4);
	tmp = (sec << 7) - sec - sec - sec;
	tmp = (tmp << 7) - tmp - tmp - tmp;
	tmp = (tmp << 7) - tmp - tmp - tmp;
	nsec = (uint32_t)hrt - (tmp << 9);

	while (nsec >= NANOSEC) {
		nsec -= NANOSEC;
		sec++;
	}

	ftv->ftv_sec = sec;
	ftv->ftv_nsec = nsec;
}

/*
 * Convert a high-resolution time from gethrtime() to a TOD (fmd_timeval_t).
 * We convert 'tod_base' to nanoseconds, adjust it based on the difference
 * between the corresponding 'hrt_base' and the event high-res time 'hrt',
 * and then repack the result into ftv_sec and ftv_nsec for our output.
 */
void
fmd_time_hrt2tod(hrtime_t hrt_base, const fmd_timeval_t *tod_base,
    hrtime_t hrt, fmd_timeval_t *ftv)
{
	fmd_time_hrt2ftv(tod_base->ftv_sec * NANOSEC +
	    tod_base->ftv_nsec + (hrt - hrt_base), ftv);
}

/*
 * Convert a TOD (fmd_timeval_t) to a high-resolution time from gethrtime().
 * Note that since TOD occurred in the past, the resulting value may be a
 * negative number according the current gethrtime() clock value.
 */
void
fmd_time_tod2hrt(hrtime_t hrt_base, const fmd_timeval_t *tod_base,
    const fmd_timeval_t *ftv, hrtime_t *hrtp)
{
	hrtime_t tod_hrt = tod_base->ftv_sec * NANOSEC + tod_base->ftv_nsec;
	hrtime_t ftv_hrt = ftv->ftv_sec * NANOSEC + ftv->ftv_nsec;

	*hrtp = hrt_base - (tod_hrt - ftv_hrt);
}

/*
 * Adjust a high-resolution time based on the low bits of time stored in ENA.
 * The assumption here in that ENA won't wrap between the time it is computed
 * and the time the error is queued (when we capture a full 64-bits of hrtime).
 * We extract the relevant ENA time bits as 't0' and subtract the difference
 * between these bits and the corresponding low bits of 'hrt' from 'hrt'.
 *
 * Under xVM dom0, the UE ereport is prepared after panic, therefore
 * the full 64-bit hrtime of 't0' can be bigger than 'hrt'.  In such case,
 * we should just return 'hrt'.
 *
 * 't0' contains only the low bits of 64bit hrtime.  It is tricky to tell
 * whether 'hrt' or 't0' happened first.  We assume there should be short
 * period between 'hrt' and 't0', therefore to check which one came first, we
 * test their subtraction against the highest bit of mask, if the bit is not
 * set, then 't0' is earlier.  This is equivalent to
 *	((hrt - t0) & mask) < ((mask + 1) / 2)
 */
hrtime_t
fmd_time_ena2hrt(hrtime_t hrt, uint64_t ena)
{
	hrtime_t t0, mask;

	switch (ENA_FORMAT(ena)) {
	case FM_ENA_FMT1:
		t0 = (ena & ENA_FMT1_TIME_MASK) >> ENA_FMT1_TIME_SHFT;
		mask = ENA_FMT1_TIME_MASK >> ENA_FMT1_TIME_SHFT;
		if (((hrt - t0) & ((mask + 1) >> 1)) == 0)
			hrt -= (hrt - t0) & mask;
		break;
	case FM_ENA_FMT2:
		t0 = (ena & ENA_FMT2_TIME_MASK) >> ENA_FMT2_TIME_SHFT;
		mask = ENA_FMT2_TIME_MASK >> ENA_FMT2_TIME_SHFT;
		if (((hrt - t0) & ((mask + 1) >> 1)) == 0)
			hrt -= (hrt - t0) & mask;
		break;
	}

	return (hrt);
}

/*
 * To implement a simulated clock, we keep track of an hrtime_t value which
 * starts at zero and is incremented only by fmd_time_addhrtime() (i.e. when
 * the driver of the simulation requests that the clock advance).  We sample
 * the native time-of-day clock once at the start of the simulation and then
 * return subsequent time-of-day values by adjusting TOD using the hrtime_t
 * clock setting.  Simulated nanosleep (fmd_time_waithrtime() entry point) is
 * implemented by waiting on fts->fts_cv for the hrtime_t to increment.
 */
static void *
fmd_simulator_init(void)
{
	fmd_timesim_t *fts = fmd_alloc(sizeof (fmd_timesim_t), FMD_SLEEP);
	struct timeval tv;

	(void) pthread_mutex_init(&fts->fts_lock, NULL);
	(void) pthread_cond_init(&fts->fts_cv, NULL);
	(void) gettimeofday(&tv, NULL);

	fts->fts_tod = (hrtime_t)tv.tv_sec * NANOSEC +
	    (hrtime_t)tv.tv_usec * (NANOSEC / MICROSEC);

	fts->fts_hrt = 0;
	fts->fts_cancel = 0;

	fmd_dprintf(FMD_DBG_TMR, "simulator tod base tv_sec=%lx hrt=%llx\n",
	    tv.tv_sec, fts->fts_tod);

	return (fts);
}

static void
fmd_simulator_fini(void *fts)
{
	if (fts != NULL)
		fmd_free(fts, sizeof (fmd_timesim_t));
}

/*ARGSUSED*/
static int
fmd_simulator_tod(struct timeval *tvp, void *tzp)
{
	fmd_timesim_t *fts = fmd.d_clockptr;
	hrtime_t tod, hrt, sec, rem;

	(void) pthread_mutex_lock(&fts->fts_lock);

	tod = fts->fts_tod;
	hrt = fts->fts_hrt;

	(void) pthread_mutex_unlock(&fts->fts_lock);

	sec = tod / NANOSEC + hrt / NANOSEC;
	rem = tod % NANOSEC + hrt % NANOSEC;

	tvp->tv_sec = sec + rem / NANOSEC;
	tvp->tv_usec = (rem % NANOSEC) / (NANOSEC / MICROSEC);

	return (0);
}

static hrtime_t
fmd_simulator_hrt(void)
{
	fmd_timesim_t *fts = fmd.d_clockptr;
	hrtime_t hrt;

	(void) pthread_mutex_lock(&fts->fts_lock);
	hrt = fts->fts_hrt;
	(void) pthread_mutex_unlock(&fts->fts_lock);

	return (hrt);
}

static void
fmd_simulator_add(hrtime_t delta)
{
	fmd_timesim_t *fts = fmd.d_clockptr;

	(void) pthread_mutex_lock(&fts->fts_lock);

	if (fts->fts_hrt + delta < fts->fts_hrt)
		fts->fts_hrt = INT64_MAX; /* do not increment past apocalypse */
	else
		fts->fts_hrt += delta;

	TRACE((FMD_DBG_TMR, "hrt clock set %llx", fts->fts_hrt));
	fmd_dprintf(FMD_DBG_TMR, "hrt clock set %llx\n", fts->fts_hrt);

	(void) pthread_cond_broadcast(&fts->fts_cv);
	(void) pthread_mutex_unlock(&fts->fts_lock);
}

static void
fmd_simulator_wait(hrtime_t delta)
{
	fmd_timesim_t *fts = fmd.d_clockptr;
	uint64_t hrt;

	(void) pthread_mutex_lock(&fts->fts_lock);

	/*
	 * If the delta causes time to wrap because we've reached the simulated
	 * apocalypse, then wait forever.  We make 'hrt' unsigned so that the
	 * while-loop comparison fts_hrt < UINT64_MAX will always return true.
	 */
	if (fts->fts_hrt + delta < fts->fts_hrt)
		hrt = UINT64_MAX;
	else
		hrt = fts->fts_hrt + delta;

	while (fts->fts_hrt < hrt && fts->fts_cancel == 0)
		(void) pthread_cond_wait(&fts->fts_cv, &fts->fts_lock);

	if (fts->fts_cancel != 0)
		fts->fts_cancel--; /* cancel has been processed */

	(void) pthread_mutex_unlock(&fts->fts_lock);
}

/*ARGSUSED*/
static void
fmd_simulator_cancel(pthread_t tid)
{
	fmd_timesim_t *fts = fmd.d_clockptr;

	(void) pthread_mutex_lock(&fts->fts_lock);
	fts->fts_cancel++;
	(void) pthread_cond_signal(&fts->fts_cv);
	(void) pthread_mutex_unlock(&fts->fts_lock);
}

/*
 * Native time is implemented by calls to gethrtime() and gettimeofday(), which
 * are stored directly in the native time ops-vector defined below.  To wait on
 * the native clock we use nanosleep(), which we can abort using a signal.  The
 * implementation assumes that callers will have a SIGALRM handler installed.
 */
static void
fmd_native_wait(hrtime_t delta)
{
	timespec_t tv;

	tv.tv_sec = delta / NANOSEC;
	tv.tv_nsec = delta % NANOSEC;

	(void) nanosleep(&tv, NULL);
}

static void
fmd_native_cancel(pthread_t tid)
{
	(void) pthread_kill(tid, SIGALRM);
}

static void
fmd_time_vnop(void)
{
}

static void *
fmd_time_nop(void)
{
	return (NULL);
}

const fmd_timeops_t fmd_timeops_native = {
	(void *(*)())fmd_time_nop,	/* fto_init */
	(void (*)())fmd_time_vnop,	/* fto_fini */
	gettimeofday,			/* fto_gettimeofday */
	gethrtime,			/* fto_gethrtime */
	(void (*)())fmd_time_vnop,	/* fto_addhrtime */
	fmd_native_wait,		/* fto_waithrtime */
	fmd_native_cancel,		/* fto_waitcancel */
};

const fmd_timeops_t fmd_timeops_simulated = {
	fmd_simulator_init,		/* fto_init */
	fmd_simulator_fini,		/* fto_fini */
	fmd_simulator_tod,		/* fto_gettimeofday */
	fmd_simulator_hrt,		/* fto_gethrtime */
	fmd_simulator_add,		/* fto_addhrtime */
	fmd_simulator_wait,		/* fto_waithrtime */
	fmd_simulator_cancel,		/* fto_waitcancel */
};
