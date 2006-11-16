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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "lpsched.h"

/*
 * terminate() - STOP A CHILD PROCESS
 *
 * Note:  If you're trying to debug lpsched, and worried about
 *        seeing lots of calls to terminate() in the debug output,
 *        don't be; it gets called once for each entry in the child
 *        process table, whether or not there's such a child.
 */

void
terminate(register EXEC *ep)
{
	int retries;		/* fix for sunsoft bugid 1108465	*/

	if (ep->pid <= 0)
		return;

	if (ep->flags & EXF_KILLED)
		return;
	ep->flags |= EXF_KILLED;

	/*
	 * Theoretically, the following "if-then" is not needed,
	 * but there's some bug in the code that occasionally
	 * prevents us from hearing from a finished child.
	 * (Kill -9 on the child would do that, of course, but
	 * the problem has occurred in other cases.)
	 */
	if (kill(-ep->pid, SIGTERM) == -1 && errno == ESRCH) {
		ep->pid = -99;
		ep->status = SIGTERM;
		ep->Errno = 0;
		DoneChildren++;
		return;
	}

	/*
	 * Start fix for sunsoft bugid 1108465
	 * the original code here was extremely optimistic, and
	 * under certain circumstances, the pid's would still be
	 * left around. here we get really serious about killing
	 * the sucker.
	 * we patiently wait for the pid to die. if it doesn't
	 * do so in a reasonable amount of time, we get more forceful.
	 * note that the original "ep->pid == -99" is a crude hack;
	 * but that the convention is being followed. sigh.
	 */
	for (retries = 5; retries > 0; retries--) {
		/* see if the process is still there		*/
		if ((kill(-ep->pid, 0) == -1) && (errno == ESRCH)) {
			ep->pid = -99;
			ep->status = SIGTERM;
			ep->Errno = 0;
			DoneChildren++;
			return;
		} else if (errno == EINTR)
			break;

		sleep(2);
	}

	/* if it's still not dead, then get more forceful	*/
	for (retries = 5; retries > 0; retries--) {
		if ((kill(-ep->pid, SIGKILL) == -1) && (errno == ESRCH)) {
			ep->pid = -99;
			ep->status = SIGTERM;
			ep->Errno = 0;
			DoneChildren++;
			return;
		}
		sleep(3);
	}
	/* end of sunsoft bugfix 1108465	*/
	/*
	 * well hardkill didn't work so just flag this request as done
	 */
	ep->pid = -99;
	ep->status = SIGTERM;
	ep->Errno = 0;
	DoneChildren++;
}
