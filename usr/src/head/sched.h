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
 * Copyright 2014 Garrett D'Amore <garrett@damore.org>
 *
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SCHED_H
#define	_SCHED_H

#include <sys/types.h>
#include <time.h>

#ifdef	__cplusplus
extern "C" {
#endif

struct sched_param {
	int	sched_priority;	/* scheduling priority */
	int	sched_pad[8];
};

/*
 * POSIX scheduling policies
 */
#define	SCHED_OTHER	0	/* traditional time-sharing scheduling class */
#define	SCHED_FIFO	1	/* real-time class: run to completion */
#define	SCHED_RR	2	/* real-time class: round-robin */
#define	SCHED_SYS	3	/* system scheduling class */
#define	SCHED_IA	4	/* interactive time-sharing class */
#define	SCHED_FSS	5	/* fair-share scheduling class */
#define	SCHED_FX	6	/* fixed-priority scheduling class */
#define	_SCHED_NEXT	7	/* first unassigned policy number */

/*
 * function prototypes
 */
int	sched_getparam(pid_t, struct sched_param *);
int	sched_setparam(pid_t, const struct sched_param *);
int	sched_getscheduler(pid_t);
int	sched_setscheduler(pid_t, int, const struct sched_param *);
int	sched_yield(void);
int	sched_get_priority_max(int);
int	sched_get_priority_min(int);
int	sched_rr_get_interval(pid_t, struct timespec *);

#ifdef	__cplusplus
}
#endif

#endif	/* _SCHED_H */
