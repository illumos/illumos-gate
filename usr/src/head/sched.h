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
 * Copyright 1993-2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SCHED_H
#define	_SCHED_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <time.h>

#ifdef	__cplusplus
extern "C" {
#endif

struct sched_param {
	int	sched_priority;	/* process execution scheduling priority */
	int	sched_nicelim;	/* nice value limit for SCHED_OTHER policy */
	int	sched_nice;	/* nice value for SCHED_OTHER policy */
	int	sched_pad[6];	/* pad to the same size as pcparms_t of */
				/* sys/priocntl.h */
				/*	sizeof(sched_priority) +	*/
				/*	sizeof(pcparms_t.pc_clparms)	*/
};

/*
 *	POSIX scheduling policies
 */
#define	SCHED_OTHER	0
#define	SCHED_FIFO	1	/* run to completion */
#define	SCHED_RR	2	/* round-robin */
#define	SCHED_SYS	3	/* sys scheduling class */
#define	SCHED_IA	4	/* interactive class */
#define	_SCHED_NEXT	5	/* first unassigned policy number */

/*
 * function prototypes
 */
#if	defined(__STDC__)
int	sched_getparam(pid_t, struct sched_param *);
int	sched_setparam(pid_t, const struct sched_param *);
int	sched_getscheduler(pid_t);
int	sched_setscheduler(pid_t, int, const struct sched_param *);
int	sched_yield(void);
int	sched_get_priority_max(int);
int	sched_get_priority_min(int);
int	sched_rr_get_interval(pid_t, struct timespec *);
#else
int	sched_getparam();
int	sched_setparam();
int	sched_getscheduler();
int	sched_setscheduler();
int	sched_yield();
int	sched_get_priority_max();
int	sched_get_priority_min();
int	sched_rr_get_interval();
#endif	/* __STDC__ */

#ifdef	__cplusplus
}
#endif

#endif	/* _SCHED_H */
