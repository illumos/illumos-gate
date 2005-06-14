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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <math.h>
#include <wait.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/time.h>
#include <signal.h>
#include <libproc.h>

static	int	look(pid_t);
static	void	hr_min_sec(char *, long);
static	void	prtime(char *, timestruc_t *);
static	int	perr(const char *);

static	void	tsadd(timestruc_t *result, timestruc_t *a, timestruc_t *b);
static	void	tssub(timestruc_t *result, timestruc_t *a, timestruc_t *b);

static	char	*command;
static	char	procname[64];

int
main(int argc, char **argv)
{
	pid_t pid;
	struct siginfo info;
	int status;

	if ((command = strrchr(argv[0], '/')) != NULL)
		command++;
	else
		command = argv[0];

	if (argc <= 1) {
		(void) fprintf(stderr,
			"usage:\t%s command [ args ... ]\n", command);
		(void) fprintf(stderr,
			"  (time a command using microstate accounting)\n");
		return (1);
	}

	switch (pid = fork()) {
	case -1:
		(void) fprintf(stderr, "%s: cannot fork: %s\n",
		    command, strerror(errno));
		return (2);
	case 0:
		(void) execvp(argv[1], &argv[1]);
		status = (errno == ENOENT) ? 127 : 126; /* see time(1) */
		(void) fprintf(stderr, "%s: failed to exec %s: %s\n",
		    command, argv[1], strerror(errno));
		_exit(status);
	}

	(void) sprintf(procname, "%d", (int)pid);	/* for perr() */
	(void) signal(SIGINT, SIG_IGN);
	(void) signal(SIGQUIT, SIG_IGN);
	(void) waitid(P_PID, pid, &info, WEXITED | WNOWAIT);

	(void) look(pid);

	(void) waitpid(pid, &status, 0);

	if (WIFEXITED(status))
		return (WEXITSTATUS(status));

	if (WIFSIGNALED(status)) {
		int sig = WTERMSIG(status);
		char name[SIG2STR_MAX];

		(void) fprintf(stderr, "%s: command terminated abnormally by "
		    "%s\n", command, proc_signame(sig, name, sizeof (name)));
	}

	return (status | WCOREFLG); /* see time(1) */
}

static int
look(pid_t pid)
{
	char pathname[100];
	int rval = 0;
	int fd;
	psinfo_t psinfo;
	prusage_t prusage;
	timestruc_t real, user, sys;
	prusage_t *pup = &prusage;

	if (proc_get_psinfo(pid, &psinfo) < 0)
		return (perr("read psinfo"));

	(void) sprintf(pathname, "/proc/%d/usage", (int)pid);
	if ((fd = open(pathname, O_RDONLY)) < 0)
		return (perr("open usage"));

	if (read(fd, &prusage, sizeof (prusage)) != sizeof (prusage))
		rval = perr("read usage");
	else {
		real = pup->pr_term;
		tssub(&real, &real, &pup->pr_create);
		user = pup->pr_utime;
		sys = pup->pr_stime;
		tsadd(&sys, &sys, &pup->pr_ttime);
		(void) fprintf(stderr, "\n");
		prtime("real", &real);
		prtime("user", &user);
		prtime("sys", &sys);
	}

	(void) close(fd);
	return (rval);
}

static void
hr_min_sec(char *buf, long sec)
{
	if (sec >= 3600)
		(void) sprintf(buf, "%ld:%.2ld:%.2ld",
			sec / 3600, (sec % 3600) / 60, sec % 60);
	else if (sec >= 60)
		(void) sprintf(buf, "%ld:%.2ld",
			sec / 60, sec % 60);
	else
		(void) sprintf(buf, "%ld", sec);
}

static void
prtime(char *name, timestruc_t *ts)
{
	char buf[32];

	hr_min_sec(buf, ts->tv_sec);
	(void) fprintf(stderr, "%-4s %8s.%.3u\n",
		name, buf, (uint_t)ts->tv_nsec/1000000);
}

static int
perr(const char *s)
{
	if (s)
		(void) fprintf(stderr, "%s: ", procname);
	else
		s = procname;
	perror(s);
	return (1);
}

static	void
tsadd(timestruc_t *result, timestruc_t *a, timestruc_t *b)
{
	result->tv_sec = a->tv_sec + b->tv_sec;
	if ((result->tv_nsec = a->tv_nsec + b->tv_nsec) >= 1000000000) {
		result->tv_nsec -= 1000000000;
		result->tv_sec += 1;
	}
}

static	void
tssub(timestruc_t *result, timestruc_t *a, timestruc_t *b)
{
	result->tv_sec = a->tv_sec - b->tv_sec;
	if ((result->tv_nsec = a->tv_nsec - b->tv_nsec) < 0) {
		result->tv_nsec += 1000000000;
		result->tv_sec -= 1;
	}
}
