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
 * Copyright (c) 1995-1997, by Sun Microsystems, Inc.
 * All rights reserved.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


/* 	Portions Copyright(c) 1988, Sun Microsystems Inc.	*/
/*	All Rights Reserved					*/

#pragma ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.1	*/

/*LINTLIBRARY*/

/*
 * Compatibility lib for SunOS's wait4().
 */

#include <sys/types.h>
#include <sys/time.h>
#include <sys/times.h>
#include <sys/wait.h>
#include <sys/siginfo.h>
#include <sys/procset.h>
#include <sys/param.h>
#include <sys/resource.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

/*
 * Since sysV does not support rusage as in BSD, an approximate approach
 * is:
 *      ...
 *      call times
 *      call waitid
 *      if ( a child is found )
 *              call times again
 *              rusage ~= diff in the 2 times call
 *      ...
 */

/*
 * forward declaration
 */
static int wstat(int, int);

pid_t
wait4(pid_t pid, int *status, int options, struct rusage *rp)
{
	struct  tms	before_tms;
	struct  tms	after_tms;
	siginfo_t	info;
	int		error;
	int 		noptions;
	idtype_t	idtype;

	if ((long)status == -1L || (long)rp == -1L) {
		errno = EFAULT;
		return (-1);
	}

	if (rp)
		(void) memset(rp, 0, sizeof (struct rusage));
	(void) memset(&info, 0, sizeof (siginfo_t));
	if (times(&before_tms) < 0)
		return (-1);	/* errno is set by times() */

	/*
	 * SunOS's wait4() only supports WNOHANG & WUNTRACED
	 */
	if (options & ~(WNOHANG|WUNTRACED))
		return (EINVAL);	/* used to be done by the kernel */
	noptions = options | WEXITED | WTRAPPED;

	/*
	 * Emulate undocumented 4.x semantics for 1186845
	 */
	if (pid < 0) {
		pid = -pid;
		idtype = P_PGID;
	} else if (pid == 0)
		idtype = P_ALL;
	else
		idtype = P_PID;

	error = waitid(idtype, pid, &info, noptions);
	if (error == 0) {
		clock_t	diffu;  /* difference in usertime (ticks) */
		clock_t	diffs;  /* difference in systemtime (ticks) */

		if ((options & WNOHANG) && (info.si_pid == 0))
			return (0);	/* no child found */

		if (rp) {
			if (times(&after_tms) < 0)
				return (-1);    /* errno set by times() */
			/*
			 * The system/user time is an approximation only !!!
			 */
			diffu = after_tms.tms_cutime - before_tms.tms_cutime;
			diffs = after_tms.tms_cstime - before_tms.tms_cstime;
			rp->ru_utime.tv_sec = diffu / HZ;
			rp->ru_utime.tv_usec = (diffu % HZ) * (1000000 / HZ);
			rp->ru_stime.tv_sec = diffs/ HZ;
			rp->ru_stime.tv_usec = (diffs % HZ) * (1000000 / HZ);
		}
		if (status)
			*status = wstat(info.si_code, info.si_status);
		return (info.si_pid);
	} else {
		return (-1);		/* error number is set by waitid() */
	}
}

/*
 * Convert the status code to old style wait status
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
