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

#ifndef	_VDSO_DEFS_H_
#define	_VDSO_DEFS_H_

#define	LX_CLOCK_REALTIME		0	/* CLOCK_REALTIME	*/
#define	LX_CLOCK_MONOTONIC		1	/* CLOCK_HIGHRES	*/
#define	LX_CLOCK_PROCESS_CPUTIME_ID	2	/* Emulated		*/
#define	LX_CLOCK_THREAD_CPUTIME_ID	3	/* Emulated		*/
#define	LX_CLOCK_MONOTONIC_RAW		4	/* CLOCK_HIGHRES	*/
#define	LX_CLOCK_REALTIME_COARSE	5	/* CLOCK_REALTIME	*/
#define	LX_CLOCK_MONOTONIC_COARSE	6	/* CLOCK_HIGHRES	*/

#if !defined(_ASM)

struct lx_timezone {
	int tz_minuteswest;	/* minutes W of Greenwich */
	int tz_dsttime;		/* type of dst correction */
};

/* Functions provided by the mach-specific vdso_subr.s */
extern comm_page_t *__vdso_find_commpage();
extern int __vdso_sys_gettimeofday(timespec_t *, struct lx_timezone *);
extern time_t __vdso_sys_time(time_t *);
extern long __vdso_sys_clock_gettime(uint_t, timespec_t *);

#endif /* !defined(_ASM) */

#endif /* _VDSO_DEFS_H_ */
