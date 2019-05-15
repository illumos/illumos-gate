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
 * Copyright 2019 Joyent, Inc.
 */

#include <cp_defs.h>
#include <vdso_defs.h>


#if defined(__i386)

long
__vdso_clock_gettime(uint_t clock_id, timespec_t *tp)
{
	comm_page_t *cp = __vdso_find_commpage();

	if (__cp_can_gettime(cp) == 0) {
		return (__vdso_sys_clock_gettime(clock_id, tp));
	}

	switch (clock_id) {
	case LX_CLOCK_REALTIME:
	case LX_CLOCK_REALTIME_COARSE:
		return (__cp_clock_gettime_realtime(cp, tp));

	case LX_CLOCK_MONOTONIC:
	case LX_CLOCK_MONOTONIC_RAW:
	case LX_CLOCK_MONOTONIC_COARSE:
		return (__cp_clock_gettime_monotonic(cp, tp));

	case LX_CLOCK_PROCESS_CPUTIME_ID:
	case LX_CLOCK_THREAD_CPUTIME_ID:
	default:
		return (__vdso_sys_clock_gettime(clock_id, tp));
	}
}

/*
 * On i386, the implementation of __cp_clock_gettime_monotonic expects that an
 * hrt2ts function is provided.  It is provided below since the vDSO is
 * operating on its own, without native libc.
 */
void
hrt2ts(hrtime_t hrt, timespec_t *tsp)
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
	tsp->tv_sec = (time_t)sec;
	tsp->tv_nsec = nsec;
}

#else

/*
 * On amd64, the __vdso_clock_gettime function is implemented in asm to stay
 * within the allowed stack budget.
 */

#endif /* defined(__i386) */


int
__vdso_gettimeofday(timespec_t *tp, struct lx_timezone *tz)
{
	if (tz != NULL) {
		tz->tz_minuteswest = 0;
		tz->tz_dsttime = 0;
	}

	if (tp != NULL) {
		comm_page_t *cp = __vdso_find_commpage();

		if (__cp_can_gettime(cp) == 0) {
			return (__vdso_sys_gettimeofday(tp, tz));
		}

		(void) __cp_clock_gettime_realtime(cp, tp);
		tp->tv_nsec /= 1000;
	}
	return (0);
}

time_t
__vdso_time(time_t *tp)
{
	comm_page_t *cp = __vdso_find_commpage();
	timespec_t ts;

	if (__cp_can_gettime(cp) == 0) {
		return (__vdso_sys_time(tp));
	}

	(void) __cp_clock_gettime_realtime(cp, &ts);
	if (tp != NULL) {
		*tp = ts.tv_sec;
	}
	return (ts.tv_sec);
}

int
__vdso_getcpu(uint_t *cpu, uint_t *node, void *tcache)
{
	comm_page_t *cp = __vdso_find_commpage();

	if (cpu != NULL) {
		*cpu = __cp_getcpu(cp);
	}
	if (node != NULL) {
		*node = 0;
	}
	return (0);
}
