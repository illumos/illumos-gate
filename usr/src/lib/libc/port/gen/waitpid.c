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

/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved  	*/

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * All of the wait*() functions are cancellation points.
 */
#pragma weak _waitpid = waitpid
#pragma weak _wait = wait

#include "lint.h"
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <wait.h>
#include <sys/types.h>
#include <sys/siginfo.h>
#include <sys/times.h>
#include <sys/resource.h>

/*
 * Convert the siginfo_t code and status fields to an old style wait status.
 */
static int
wstat(int code, int status)
{
	int stat = (status & 0377);

	switch (code) {
	case CLD_EXITED:
		stat <<= 8;
		break;
	case CLD_DUMPED:
		stat |= WCOREFLG;
		break;
	case CLD_KILLED:
		break;
	case CLD_TRAPPED:
	case CLD_STOPPED:
		stat <<= 8;
		stat |= WSTOPFLG;
		break;
	case CLD_CONTINUED:
		stat = WCONTFLG;
		break;
	}
	return (stat);
}

pid_t
waitpid(pid_t pid, int *stat_loc, int options)
{
	idtype_t idtype;
	id_t id;
	siginfo_t info;
	int error;

	if (pid > 0) {
		idtype = P_PID;
		id = pid;
	} else if (pid < -1) {
		idtype = P_PGID;
		id = -pid;
	} else if (pid == -1) {
		idtype = P_ALL;
		id = 0;
	} else {
		idtype = P_PGID;
		id = getpgid(0);
	}

	options |= (WEXITED|WTRAPPED);

	if ((error = waitid(idtype, id, &info, options)) < 0)
		return (error);

	if (stat_loc)
		*stat_loc = wstat(info.si_code, info.si_status);

	return (info.si_pid);
}

pid_t
wait(int *stat_loc)
{
	return (waitpid(-1, stat_loc, 0));
}

pid_t
wait4(pid_t pid, int *stat_loc, int options, struct rusage *rp)
{
	struct tms	before_tms;
	struct tms	after_tms;
	siginfo_t	info;
	int		error;
	int		noptions;
	idtype_t	idtype;

	if (rp)
		(void) memset(rp, 0, sizeof (struct rusage));
	(void) memset(&info, 0, sizeof (siginfo_t));

	if (times(&before_tms) == (clock_t)-1)
		return (-1);		/* errno is set by times() */

	/*
	 * SunOS's wait4() previously supported only WNOHANG &
	 * WUNTRACED.  XPG4v2 mandates that wait3() (which calls
	 * wait4()) also support WCONTINUED.
	 */
	if (options & ~(WNOHANG|WUNTRACED|WCONTINUED)) {
		errno = EINVAL;
		return (-1);
	}
	noptions = options | WEXITED | WTRAPPED;

	/*
	 * Emulate undocumented 4.x semantics for 1186845
	 */
	if (pid < 0) {
		pid = -pid;
		idtype = P_PGID;
	} else if (pid == 0) {
		idtype = P_ALL;
	} else {
		idtype = P_PID;
	}

	error = waitid(idtype, pid, &info, noptions);
	if (error == 0) {
		clock_t diffu;	/* difference in usertime (ticks) */
		clock_t diffs;	/* difference in systemtime (ticks) */
		clock_t hz;

		if ((options & WNOHANG) && info.si_pid == 0)
			return (0);	/* no child found */

		if (rp) {
			if (times(&after_tms) == (clock_t)-1)
				return (-1);	/* errno set by times() */
			/*
			 * The system/user time is an approximation only !!!
			 */
			diffu = after_tms.tms_cutime - before_tms.tms_cutime;
			diffs = after_tms.tms_cstime - before_tms.tms_cstime;
			hz = CLK_TCK;
			rp->ru_utime.tv_sec = diffu / hz;
			rp->ru_utime.tv_usec = (diffu % hz) * (1000000 / hz);
			rp->ru_stime.tv_sec = diffs / hz;
			rp->ru_stime.tv_usec = (diffs % hz) * (1000000 / hz);
		}
		if (stat_loc)
			*stat_loc = wstat(info.si_code, info.si_status);
		return (info.si_pid);
	} else {
		return (-1);		/* error number is set by waitid() */
	}
}

pid_t
wait3(int *stat_loc, int options, struct rusage *rp)
{
	return (wait4(0, stat_loc, options, rp));
}
