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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include "statcommon.h"

#include <stdarg.h>
#include <signal.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>

extern char *cmdname;
extern int caught_cont;

/*PRINTFLIKE2*/
void
fail(int do_perror, char *message, ...)
{
	va_list args;
	int save_errno = errno;

	va_start(args, message);
	(void) fprintf(stderr, "%s: ", cmdname);
	(void) vfprintf(stderr, message, args);
	va_end(args);
	if (do_perror)
		(void) fprintf(stderr, ": %s", strerror(save_errno));
	(void) fprintf(stderr, "\n");
	exit(2);
}

/*
 * Sleep until *wakeup + interval, keeping cadence where desired
 *
 * *wakeup -	The time we last wanted to wake up. Updated.
 * interval -	We want to sleep until *wakeup + interval
 * forever -	Running for infinite periods, so cadence not important
 * *caught_cont - Global set by signal handler if we got a SIGCONT
 */
void
sleep_until(hrtime_t *wakeup, hrtime_t interval, int forever,
    int *caught_cont)
{
	hrtime_t now, pause, pause_left;
	struct timespec pause_tv;
	int status;

	now = gethrtime();
	pause = *wakeup + interval - now;

	if (pause <= 0 || pause < (interval / 4))
		if (forever || *caught_cont) {
			/* Reset our cadence (see comment below) */
			*wakeup = now + interval;
			pause = interval;
		} else {
			/*
			 * If we got here, then the time between the
			 * output we just did, and the scheduled time
			 * for the next output is < 1/4 of our requested
			 * interval AND the number of intervals has been
			 * requested AND we have never caught a SIGCONT
			 * (so we have never been suspended).  In this
			 * case, we'll try to stay to the desired
			 * cadence, and we will pause for 1/2 the normal
			 * interval this time.
			 */
			pause = interval / 2;
			*wakeup += interval;
		}
	else
		*wakeup += interval;
	if (pause < 1000)
		/* Near enough */
		return;

	/* Now do the actual sleep */
	pause_left = pause;
	do {
		pause_tv.tv_sec = pause_left / NANOSEC;
		pause_tv.tv_nsec = pause_left % NANOSEC;
		status = nanosleep(&pause_tv, (struct timespec *)NULL);
		if (status < 0)
			if (errno == EINTR) {
				now = gethrtime();
				pause_left = *wakeup - now;
				if (pause_left < 1000)
					/* Near enough */
					return;
			} else {
				fail(1, "nanosleep failed");
			}
	} while (status != 0);
}

/*
 * Signal handler - so we can be aware of SIGCONT
 */
void
cont_handler(int sig_number)
{
	/* Re-set the signal handler */
	(void) signal(sig_number, cont_handler);
	caught_cont = 1;
}
