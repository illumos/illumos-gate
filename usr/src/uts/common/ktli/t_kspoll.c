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
 * Copyright 1997 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * University Copyright- Copyright (c) 1982, 1986, 1988
 * The Regents of the University of California
 * All Rights Reserved
 *
 * University Acknowledgment- Portions of this document are derived from
 * software developed by the University of California, Berkeley, and its
 * contributors.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * This function waits for timo clock ticks for something to arrive on
 * the specified stream. If more than one client is hanging off of a
 * single endpoint, and at least one has specified a non-zero timeout,
 * then all will be woken.
 *
 * Returns:
 * 	0 on success or positive error code. On
 * 	success, "events" is set to
 *	 0	on timeout or no events(timout = 0),
 *	 1	if desired event has occurred
 *
 * Most of the code is from strwaitq().
 */

#include <sys/param.h>
#include <sys/types.h>
#include <sys/proc.h>
#include <sys/file.h>
#include <sys/user.h>
#include <sys/vnode.h>
#include <sys/errno.h>
#include <sys/stream.h>
#include <sys/ioctl.h>
#include <sys/stropts.h>
#include <sys/strsubr.h>
#include <sys/tihdr.h>
#include <sys/timod.h>
#include <sys/tiuser.h>
#include <sys/t_kuser.h>
#include <sys/signal.h>
#include <sys/siginfo.h>
#include <sys/time.h>
#include <sys/debug.h>

/*
 * Poll for an input event.
 *
 * timo is measured in ticks
 */
int
t_kspoll(TIUSER *tiptr, int timo, int waitflg, int *events)
{
	file_t		*fp;
	vnode_t		*vp;
	klwp_t		*lwp = ttolwp(curthread);
	clock_t		timout;	/* milliseconds */
	int		error;
	u_char 		pri;
	int 		pflag;
	rval_t		rval;

	fp = tiptr->fp;
	vp = fp->f_vnode;

	if (events == NULL || ((waitflg & READWAIT) == 0))
		return (EINVAL);

	/* Convert from ticks to milliseconds */
	if (timo < 0)
		timout = -1;
	else
		timout = TICK_TO_MSEC(timo);

	/*
	 * Indicate that the lwp is not to be stopped while doing
	 * this network traffic.  This is to avoid deadlock while
	 * debugging a process via /proc.
	 */
	if (lwp != NULL)
		lwp->lwp_nostop++;

	if (waitflg & NOINTR)
		pflag = MSG_ANY | MSG_HOLDSIG;
	else
		pflag = MSG_ANY;
	pri = 0;
	error = kstrgetmsg(vp, NULL, NULL, &pri, &pflag, timout, &rval);

	if (lwp != NULL)
		lwp->lwp_nostop--;

	/* Set the return *events. */
	if (error != 0) {
		if (error == ETIME) {
			*events = 0;
			error = 0;
		}
		return (error);
	}
	*events = 1;
	return (0);
}
