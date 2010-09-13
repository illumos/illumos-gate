/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_FMD_TIME_H
#define	_FMD_TIME_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>

#ifdef	__cplusplus
extern "C" {
#endif

typedef struct fmd_timeval {
	uint64_t ftv_sec;	/* seconds since gettimeofday(3C) Epoch */
	uint64_t ftv_nsec;	/* nanoseconds past value of ftv_sec */
} fmd_timeval_t;

typedef struct fmd_timeops {
	void *(*fto_init)(void);
	void (*fto_fini)(void *);
	int (*fto_gettimeofday)(struct timeval *, void *);
	hrtime_t (*fto_gethrtime)(void);
	void (*fto_addhrtime)(hrtime_t);
	void (*fto_waithrtime)(hrtime_t);
	void (*fto_waitcancel)(pthread_t);
} fmd_timeops_t;

typedef struct fmd_timesim {
	pthread_mutex_t fts_lock; /* lock protecting contents of fmd_timesim */
	pthread_cond_t fts_cv;	/* condition variable for timerq wait */
	hrtime_t fts_tod;	/* time-of-day nsec corresponding to hrt=0 */
	hrtime_t fts_hrt;	/* hrtime clock in simulated universe */
	uint_t fts_cancel;	/* count of pending fto_waitcancel()s */
} fmd_timesim_t;

extern const fmd_timeops_t fmd_timeops_native;
extern const fmd_timeops_t fmd_timeops_simulated;

extern void fmd_time_gettimeofday(struct timeval *);
extern hrtime_t fmd_time_gethrtime(void);
extern void fmd_time_addhrtime(hrtime_t);
extern void fmd_time_waithrtime(hrtime_t);
extern void fmd_time_waitcancel(pthread_t);
extern void fmd_time_sync(fmd_timeval_t *, hrtime_t *, uint_t);

extern void fmd_time_hrt2tod(hrtime_t, const fmd_timeval_t *,
    hrtime_t, fmd_timeval_t *);

extern void fmd_time_tod2hrt(hrtime_t, const fmd_timeval_t *,
    const fmd_timeval_t *, hrtime_t *);

extern hrtime_t fmd_time_ena2hrt(hrtime_t, uint64_t);

#ifdef	__cplusplus
}
#endif

#endif	/* _FMD_TIME_H */
