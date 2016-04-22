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

#include <cp_defs.h>


struct lx_timezone {
	int tz_minuteswest;	/* minutes W of Greenwich */
	int tz_dsttime;		/* type of dst correction */
};

extern comm_page_t *__vdso_find_commpage();
extern int __vdso_sys_gettimeofday(timespec_t *, struct lx_timezone *);
extern time_t __vdso_sys_time(timespec_t *);
extern long __vdso_sys_clock_gettime(uint_t, timespec_t *);

#define	LX_CLOCK_REALTIME		0	/* CLOCK_REALTIME	*/
#define	LX_CLOCK_MONOTONIC		1	/* CLOCK_HIGHRES	*/
#define	LX_CLOCK_PROCESS_CPUTIME_ID	2	/* Emulated		*/
#define	LX_CLOCK_THREAD_CPUTIME_ID	3	/* Emulated		*/
#define	LX_CLOCK_MONOTONIC_RAW		4	/* CLOCK_HIGHRES	*/
#define	LX_CLOCK_REALTIME_COARSE	5	/* CLOCK_REALTIME	*/
#define	LX_CLOCK_MONOTONIC_COARSE	6	/* CLOCK_HIGHRES	*/


void
__hrt2ts(hrtime_t hrt, timespec_t *tsp)
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

int
__vdso_gettimeofday(timespec_t *tp, struct lx_timezone *tz)
{
	comm_page_t *cp = __vdso_find_commpage();

	if (__cp_can_gettime(cp) != 0) {
		return (__vdso_sys_gettimeofday(tp, tz));
	}

	if (tp != NULL) {
		long usec, nsec;

		__cp_clock_gettime_realtime(cp, tp);

		nsec = tp->tv_nsec;
		usec = nsec + (nsec >> 2);
		usec = nsec + (usec >> 1);
		usec = nsec + (usec >> 2);
		usec = nsec + (usec >> 4);
		usec = nsec - (usec >> 3);
		usec = nsec + (usec >> 2);
		usec = nsec + (usec >> 3);
		usec = nsec + (usec >> 4);
		usec = nsec + (usec >> 1);
		usec = nsec + (usec >> 6);
		usec = usec >> 10;
		tp->tv_nsec = usec;
	}

	if (tz != NULL) {
		tz->tz_minuteswest = 0;
		tz->tz_dsttime = 0;
	}

	return (0);
}

time_t
__vdso_time(timespec_t *tp)
{
	comm_page_t *cp = __vdso_find_commpage();
	timespec_t ts;

	if (__cp_can_gettime(cp) != 0) {
		return (__vdso_sys_time(tp));
	}

	__cp_clock_gettime_realtime(cp, &ts);
	if (tp != NULL) {
		tp->tv_sec = ts.tv_sec;
		tp->tv_nsec = 0;
	}
	return (ts.tv_sec);
}

long
__vdso_clock_gettime(uint_t clock_id, timespec_t *tp)
{
	comm_page_t *cp = __vdso_find_commpage();

	if (__cp_can_gettime(cp) != 0) {
		return (__vdso_sys_clock_gettime(clock_id, tp));
	}

	switch (clock_id) {
	case LX_CLOCK_REALTIME:
	case LX_CLOCK_REALTIME_COARSE:
		__cp_clock_gettime_realtime(cp, tp);
		return (0);

	case LX_CLOCK_MONOTONIC:
	case LX_CLOCK_MONOTONIC_RAW:
	case LX_CLOCK_MONOTONIC_COARSE:
		__hrt2ts(__cp_gethrtime(cp), tp);
		return (0);

	case LX_CLOCK_PROCESS_CPUTIME_ID:
	case LX_CLOCK_THREAD_CPUTIME_ID:
	default:
		break;
	}
	return (__vdso_sys_clock_gettime(clock_id, tp));
}

long
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
