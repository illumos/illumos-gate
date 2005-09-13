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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * rusage
 */

#include <locale.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <signal.h>

void
fprintt(s, tv)
	char *s;
	struct timeval *tv;
{

	(void) fprintf(stderr, gettext("%d.%02d %s "),
		tv->tv_sec, tv->tv_usec/10000, s);
}

int
main(int argc, char **argv)
{
	union wait status;
	int options = 0;
	int p;
	struct timeval before, after;
	struct rusage ru;
	struct timezone tz;

	(void) setlocale(LC_ALL, "");

#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN "SYS_TEST"
#endif
	(void) textdomain(TEXT_DOMAIN);

	if (argc <= 1)
		exit(0);
	(void) gettimeofday(&before, &tz);

	/* fork a child process to run the command */

	p = fork();
	if (p < 0) {
		perror("rusage");
		exit(1);
	}

	if (p == 0) {

		/* exec the command specified */

		execvp(argv[1], &argv[1]);
		perror(argv[1]);
		exit(1);
	}

	/* parent code - wait for command to complete */

	(void) signal(SIGINT, SIG_IGN);
	(void) signal(SIGQUIT, SIG_IGN);
	while (wait3(&status.w_status, options, &ru) != p)
		;

	/* get closing time of day */
	(void) gettimeofday(&after, &tz);

	/* check for exit status of command */

	if ((status.w_termsig) != 0)
		(void) fprintf(stderr,
		    gettext("Command terminated abnormally.\n"));

	/* print an accounting summary line */

	after.tv_sec -= before.tv_sec;
	after.tv_usec -= before.tv_usec;
	if (after.tv_usec < 0) {
		after.tv_sec--;
		after.tv_usec += 1000000;
	}
	fprintt(gettext("real"), &after);
	fprintt(gettext("user"), &ru.ru_utime);
	fprintt(gettext("sys"), &ru.ru_stime);
	(void) fprintf(stderr, gettext("%d pf %d pr %d sw"),
		ru.ru_majflt,
		ru.ru_minflt,
		ru.ru_nswap);
	(void) fprintf(stderr, gettext(" %d rb %d wb %d vcx %d icx"),
		ru.ru_inblock,
		ru.ru_oublock,
		ru.ru_nvcsw,
		ru.ru_nivcsw);
	(void) fprintf(stderr, gettext(" %d mx %d ix %d id %d is"),
		ru.ru_maxrss,
		ru.ru_ixrss,
		ru.ru_idrss,
		ru.ru_isrss);

	(void) fprintf(stderr, "\n");
	return ((int)status.w_retcode);
}
