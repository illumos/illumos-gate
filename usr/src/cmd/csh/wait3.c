/*
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved	*/

/*
 * Copyright (c) 1980 Regents of the University of California.
 * All rights reserved. The Berkeley Software License Agreement
 * specifies the terms and conditions for redistribution.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Compatibility lib for BSD's wait3(). It is not
 * binary compatible, since BSD's WNOHANG and WUNTRACED
 * carry different #define values.
 */
#include <errno.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/times.h>
#include <wait.h>
#include <sys/siginfo.h>
#include <sys/procset.h>
#include <sys/param.h>
#include <sys/resource.h>

/*
 * Since sysV does not support rusage as in BSD, an approximate approach
 * is:
 *	...
 *	call times
 *	call waitid
 *	if ( a child is found )
 *		call times again
 *		rusage ~= diff in the 2 times call
 *	...
 *
 */

/*
 * XXX:  There is now a wait3 function in libc which should be used instead
 * of this local version of wait3.  With the addition of a wait3 prototype
 * in <sys/wait.h> as per the X/Open XPG4v2 specification, compilation of
 * the csh utility will result in warnings, hence the renaming of the local
 * version.  Using the libc wait3 rather than the local version results in
 * a failure with csh, however, this version should eventually be dropped
 * in favor of the libc wait3 with appropriate updates made to sh.proc.c
 * to account for the difference in implementation of the local versus
 * the libc versions.  This should probably be done as part of an overall
 * effort to rid csh of local versions of functions now in libc.
 */

static int wstat(int code, int status);

pid_t
csh_wait3(int *status, int options, struct rusage *rp)
{
	struct tms before_tms;
	struct tms after_tms;
	siginfo_t info;
	int error;

	if (rp)
		memset((void *)rp, 0, sizeof (struct rusage));
	memset((void *)&info, 0, sizeof (siginfo_t));
	if (times(&before_tms) == -1)
		return (-1);	/* errno is set by times() */

	/*
	 * BSD's wait3() only supports WNOHANG & WUNTRACED
	 */
	options |= (WNOHANG|WUNTRACED|WEXITED|WSTOPPED|WTRAPPED|WCONTINUED);
	error = waitid(P_ALL, 0, &info, options);
	if (error == 0) {
		clock_t	diffu;	/* difference in usertime (ticks) */
		clock_t	diffs;	/* difference in systemtime (ticks) */

		if ((options & WNOHANG) && (info.si_pid == 0))
			return (0);	/* no child found */

		if (rp) {
			if (times(&after_tms) == -1)
				return (-1);	/* errno set by times() */
			/*
			 * The system/user time is an approximation only !!!
			 */
			diffu = after_tms.tms_cutime - before_tms.tms_cutime;
			diffs = after_tms.tms_cstime - before_tms.tms_cstime;
			rp->ru_utime.tv_sec = diffu/HZ;
			rp->ru_utime.tv_usec = ((diffu % HZ) * 1000000) / HZ;
			rp->ru_stime.tv_sec = diffs/HZ;
			rp->ru_stime.tv_usec = ((diffs % HZ) * 1000000) / HZ;
		}
		*status = wstat(info.si_code, info.si_status);
		return (info.si_pid);

	} else {
		return (-1);	/* error number is set by waitid() */
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

pid_t
csh_wait_noreap(void)
{
	siginfo_t info;

	if (waitid(P_ALL, 0, &info,
	    WEXITED | WTRAPPED | WSTOPPED | WCONTINUED | WNOWAIT) != 0)
		return (-1);
	return (info.si_pid);
}
