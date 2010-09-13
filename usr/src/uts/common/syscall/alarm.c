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
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved	*/


/*
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/param.h>
#include <sys/types.h>
#include <sys/sysmacros.h>
#include <sys/systm.h>
#include <sys/errno.h>
#include <sys/signal.h>
#include <sys/proc.h>
#include <sys/time.h>
#include <sys/cmn_err.h>
#include <sys/debug.h>

static void
sigalarm2proc(void *arg)
{
	proc_t *p = arg;

	mutex_enter(&p->p_lock);
	p->p_alarmid = 0;
	sigtoproc(p, NULL, SIGALRM);
	mutex_exit(&p->p_lock);
}

int
alarm(int deltat)
{
	proc_t *p = ttoproc(curthread);
	clock_t del = 0;
	clock_t ret;
	timeout_id_t tmp_id;
	clock_t delta = (uint_t)deltat;

	/*
	 * We must single-thread this code relative to other
	 * lwps in the same process also performing an alarm().
	 * The mutex dance in the while loop is necessary because
	 * we cannot call untimeout() while holding a lock that
	 * is grabbed by the timeout function, sigalarm2proc().
	 * We can, however, hold p->p_lock across realtime_timeout().
	 */
	mutex_enter(&p->p_lock);
	while ((tmp_id = p->p_alarmid) != 0) {
		p->p_alarmid = 0;
		mutex_exit(&p->p_lock);
		del = untimeout(tmp_id);
		mutex_enter(&p->p_lock);
	}

	if (del < 0)
		ret = 0;
	else
		ret = (del + hz - 1) / hz;	/* convert to seconds */

	/*
	 * Our implementation defined limit for alarm is
	 * LONG_MAX / hz. Anything larger gets truncated
	 * to that limit. If delta is negative we can
	 * assume a wrap has occurred so peg delta in
	 * that case too. 64 bit platforms have higher limit.
	 */
	if (delta > (LONG_MAX / hz) || delta < 0)
		delta = LONG_MAX / hz;

	if (delta)
		p->p_alarmid = realtime_timeout(sigalarm2proc, p, delta * hz);
	mutex_exit(&p->p_lock);
	return (ret);
}
