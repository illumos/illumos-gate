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
 *
 * Portions Copyright 2008 Chad Mynhier
 */
/*
 * Copyright (c) 2014, Joyent, Inc.  All rights reserved.
 */

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
#include <limits.h>
#include "ptools_common.h"

static	int	look(pid_t);
static	void	hr_min_sec(char *, long);
static	void	prtime(char *, timestruc_t *);
static	int	perr(const char *);

static	void	tsadd(timestruc_t *result, timestruc_t *a, timestruc_t *b);
static	void	tssub(timestruc_t *result, timestruc_t *a, timestruc_t *b);
static	void	hrt2ts(hrtime_t hrt, timestruc_t *tsp);

static	char	*command;
static	char	*pidarg;
static	char	procname[64];

static	int	Fflag;
static	int	mflag;
static	int	errflg;
static	int	pflag;

static int
ptime_pid(const char *pidstr)
{
	struct ps_prochandle *Pr;
	pid_t pid;
	int gret;

	if ((Pr = proc_arg_grab(pidstr, PR_ARG_PIDS,
	    Fflag | PGRAB_RDONLY, &gret)) == NULL) {
		(void) fprintf(stderr, "%s: cannot examine %s: %s\n",
		    command, pidstr, Pgrab_error(gret));
		return (1);
	}

	pid = Pstatus(Pr)->pr_pid;
	(void) sprintf(procname, "%d", (int)pid);	/* for perr() */
	(void) look(pid);
	Prelease(Pr, 0);
	return (0);
}

int
main(int argc, char **argv)
{
	int opt, exit;
	pid_t pid;
	struct siginfo info;
	int status;
	int gret;
	struct ps_prochandle *Pr;
	char *pp, *np;

	if ((command = strrchr(argv[0], '/')) != NULL)
		command++;
	else
		command = argv[0];

	while ((opt = getopt(argc, argv, "Fhmp:")) != EOF) {
		switch (opt) {
		case 'F':		/* force grabbing (no O_EXCL) */
			Fflag = PGRAB_FORCE;
			break;
		case 'm':		/* microstate accounting */
			mflag = 1;
			break;
		case 'p':
			pflag = 1;
			pidarg = optarg;
			break;
		default:
			errflg = 1;
			break;
		}
	}

	argc -= optind;
	argv += optind;

	if (((pidarg != NULL) ^ (argc < 1)) || errflg) {
		(void) fprintf(stderr,
		    "usage:\t%s [-mh] [-p pidlist | command [ args ... ]]\n",
		    command);
		(void) fprintf(stderr,
		    "  (time a command using microstate accounting)\n");
		return (1);
	}

	if (pflag) {
		exit = 0;
		(void) signal(SIGINT, SIG_IGN);
		(void) signal(SIGQUIT, SIG_IGN);
		pp = pidarg;
		if ((np = strchr(pp, ' ')) != NULL ||
		    (np = strchr(pp, ',')) != NULL)
			pflag++;
		while (np != NULL) {
			*np = '\0';
			exit |= ptime_pid(pp);
			pp = np + 1;
			np = strchr(pp, ' ');
			if (np == NULL)
				np = strchr(pp, ',');
		}
		exit |= ptime_pid(pp);
		return (exit);
	}


	if ((Pr = Pcreate(argv[0], &argv[0], &gret, NULL, 0)) == NULL) {
		(void) fprintf(stderr, "%s: failed to exec %s: %s\n",
		    command, argv[0], Pcreate_error(gret));
		return (1);
	}
	if (Psetrun(Pr, 0, 0) == -1) {
		(void) fprintf(stderr, "%s: failed to set running %s: "
		    "%s\n", command, argv[0], strerror(errno));
		return (1);
	}

	pid = Pstatus(Pr)->pr_pid;

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

		(void) fprintf(stderr, "%s: command terminated "
		    "abnormally by %s\n", command,
		    proc_signame(sig, name, sizeof (name)));
	}

	return (status | WCOREFLG); /* see time(1) */
}

static int
look(pid_t pid)
{
	char pathname[PATH_MAX];
	int rval = 0;
	int fd;
	psinfo_t psinfo;
	prusage_t prusage;
	timestruc_t real, user, sys;
	hrtime_t hrtime;
	prusage_t *pup = &prusage;

	if (proc_get_psinfo(pid, &psinfo) < 0)
		return (perr("read psinfo"));

	(void) proc_snprintf(pathname, sizeof (pathname), "/proc/%d/usage",
	    (int)pid);
	if ((fd = open(pathname, O_RDONLY)) < 0)
		return (perr("open usage"));

	if (read(fd, &prusage, sizeof (prusage)) != sizeof (prusage))
		rval = perr("read usage");
	else {
		if (pidarg) {
			hrtime = gethrtime();
			hrt2ts(hrtime, &real);
		} else {
			real = pup->pr_term;
		}
		tssub(&real, &real, &pup->pr_create);
		user = pup->pr_utime;
		sys = pup->pr_stime;
		if (!mflag)
			tsadd(&sys, &sys, &pup->pr_ttime);

		(void) fprintf(stderr, "\n");
		if (pflag > 1)
			(void) fprintf(stderr, "%d:\t%.70s\n",
			    (int)psinfo.pr_pid, psinfo.pr_psargs);
		prtime("real", &real);
		prtime("user", &user);
		prtime("sys", &sys);

		if (mflag) {
			prtime("trap", &pup->pr_ttime);
			prtime("tflt", &pup->pr_tftime);
			prtime("dflt", &pup->pr_dftime);
			prtime("kflt", &pup->pr_kftime);
			prtime("lock", &pup->pr_ltime);
			prtime("slp", &pup->pr_slptime);
			prtime("lat", &pup->pr_wtime);
			prtime("stop", &pup->pr_stoptime);
		}
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

	(void) fprintf(stderr, "%-4s %8s.%.9u\n",
	    name, buf, (uint_t)ts->tv_nsec);
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

static void
hrt2ts(hrtime_t hrt, timestruc_t *tsp)
{
	tsp->tv_sec = hrt / NANOSEC;
	tsp->tv_nsec = hrt % NANOSEC;
}
