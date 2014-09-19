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
 * Copyright 2014 Joyent, Inc.  All rights reserved.
 */

#include <errno.h>
#include <time.h>
#include <string.h>
#include <strings.h>
#include <sys/times.h>
#include <sys/lx_syscall.h>
#include <sys/lx_misc.h>

/*
 * time() - This cannot be passthrough because on Linux a bad buffer will
 *	    set errno to EFAULT, and on Illumos the failure mode is documented
 *	    as "undefined."
 *
 *	    (At present, Illumos' time(2) will segmentation fault, as the call
 *	    is simply a libc wrapper atop the time() syscall that will
 *	    dereference the passed  pointer if it is non-zero.)
 */
long
lx_time(uintptr_t p1)
{
	time_t ret = time((time_t *)0);

	if ((ret == (time_t)-1) ||
	    ((p1 != 0) && (uucopy(&ret, (time_t *)p1, sizeof (ret)) != 0)))
		return (-errno);

	return (ret);
}

/*
 * times() - The Linux implementation avoids writing to NULL, while Illumos
 *	     returns EFAULT.
 */
long
lx_times(uintptr_t p1)
{
	clock_t ret;
	struct tms buf, *tp = (struct tms *)p1;

	ret = times(&buf);

	if ((ret == -1) ||
	    ((tp != NULL) && uucopy((void *)&buf, tp, sizeof (buf)) != 0))
		return (-errno);

	return ((ret == -1) ? -errno : ret);
}

/*
 * setitimer() - the Linux implementation can handle tv_usec values greater
 *		 than 1,000,000 where Illumos would return EINVAL.
 *
 *		 There's still an issue here where Linux can handle a
 *		 tv_sec value greater than 100,000,000 but Illumos cannot,
 *		 but that would also mean setting an interval timer to fire
 *		 over _three years_ in the future so it's unlikely anything
 *		 other than Linux test suites will trip over it.
 */
long
lx_setitimer(uintptr_t p1, uintptr_t p2, uintptr_t p3)
{
	struct itimerval itv;
	struct itimerval *itp = (struct itimerval *)p2;

	if (itp != NULL) {
		if (uucopy(itp, &itv, sizeof (itv)) != 0)
			return (-errno);

		/*
		 * Adjust any tv_usec fields >= 1,000,000 by adding any whole
		 * seconds so indicated to tv_sec and leaving tv_usec as the
		 * remainder.
		 */
		if (itv.it_interval.tv_usec >= MICROSEC) {
			itv.it_interval.tv_sec +=
			    itv.it_interval.tv_usec / MICROSEC;

			itv.it_interval.tv_usec %= MICROSEC;
		}
		if (itv.it_value.tv_usec >= MICROSEC) {
			itv.it_value.tv_sec +=
			    itv.it_value.tv_usec / MICROSEC;

			itv.it_value.tv_usec %= MICROSEC;
		}

		itp = &itv;
	}

	return ((setitimer((int)p1, itp, (struct itimerval *)p3) != 0) ?
	    -errno : 0);
}

/*
 * NOTE: The Linux man pages state this structure is obsolete and is
 *	 unsupported, so it is declared here for sizing purposes only.
 */
struct lx_timezone {
	int tz_minuteswest;	/* minutes W of Greenwich */
	int tz_dsttime;		/* type of dst correction */
};

/*
 * lx_gettimeofday() and lx_settimeofday() are implemented here rather than
 * as pass-through calls to Solaris' libc due to the need to return EFAULT
 * for a bad buffer rather than die with a segmentation fault.
 */
long
lx_gettimeofday(uintptr_t p1, uintptr_t p2)
{
	struct timeval tv;
	struct lx_timezone tz;

	bzero(&tz, sizeof (tz));
	(void) gettimeofday(&tv, NULL);

	if ((p1 != NULL) &&
	    (uucopy(&tv, (struct timeval *)p1, sizeof (tv)) < 0))
		return (-errno);

	/*
	 * The Linux man page states use of the second parameter is obsolete,
	 * but gettimeofday(2) should still return EFAULT if it is set
	 * to a bad non-NULL pointer (sigh...)
	 */
	if ((p2 != NULL) &&
	    (uucopy(&tz, (struct lx_timezone *)p2, sizeof (tz)) < 0))
		return (-errno);

	return (0);
}

long
lx_settimeofday(uintptr_t p1, uintptr_t p2)
{
	struct timeval tv;
	struct lx_timezone tz;

	if ((p1 != NULL) &&
	    (uucopy((struct timeval *)p1, &tv, sizeof (tv)) < 0))
		return (-errno);

	/*
	 * The Linux man page states use of the second parameter is obsolete,
	 * but settimeofday(2) should still return EFAULT if it is set
	 * to a bad non-NULL pointer (sigh...)
	 */
	if ((p2 != NULL) &&
	    (uucopy((struct lx_timezone *)p2, &tz, sizeof (tz)) < 0))
		return (-errno);

	if ((p1 != NULL) && (settimeofday(&tv, NULL) < 0))
		return (-errno);

	return (0);
}
