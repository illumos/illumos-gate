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
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <ctype.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <libproc.h>
#include <limits.h>
#include "ptools_common.h"

#define	NOREAP_TIME 60		/* wait 60 seconds before allow a reap */

static volatile int interrupt;
static int Fflag;
static char *command;

static void
intr(int sig)
{
	interrupt = sig;
}

static int
open_usage(pid_t pid, int *perr)
{
	char path[PATH_MAX];
	struct stat64 st;
	int fd;

	(void) proc_snprintf(path, sizeof (path), "/proc/%d/usage", (int)pid);

	/*
	 * Attempt to open the usage file, and return the fd if we can
	 * confirm this is a regular file provided by /proc.
	 */
	if ((fd = open64(path, O_RDONLY)) >= 0) {
		if (fstat64(fd, &st) != 0 || !S_ISREG(st.st_mode) ||
		    strcmp(st.st_fstype, "proc") != 0) {
			(void) close(fd);
			fd = -1;
		}
	} else if (errno == EACCES || errno == EPERM)
		*perr = G_PERM;

	return (fd);
}

static int
proc_usage(pid_t pid, prusage_t *pup, int *perr)
{
	int fd;

	*perr = G_NOPROC;

	if ((fd = open_usage(pid, perr)) != -1) {
		if (read(fd, pup, sizeof (prusage_t)) == sizeof (prusage_t)) {
			*perr = 0;
			(void) close(fd);
			return (0);
		}

		/*
		 * If the read failed, the process may have gone away.
		 */
		(void) close(fd);
	}
	return (-1);
}

/*
 * Force the parent process (ppid) to wait for its child process (pid).
 */
static int
reap(char *arg, pid_t *reap_pid, int *exit_status)
{
	struct ps_prochandle *Pr;
	siginfo_t siginfo;
	psinfo_t psinfo;
	prusage_t usage;
	pid_t pid, ppid;
	time_t elapsed;
	int gret;

	/*
	 * get the specified pid and the psinfo struct
	 */
	if ((pid = proc_arg_psinfo(arg, PR_ARG_PIDS, &psinfo, &gret)) == -1) {
		(void) fprintf(stderr, "%s: cannot examine %s: %s\n",
		    command, arg, Pgrab_error(gret));
		return (1);
	}

	if (psinfo.pr_nlwp != 0) {
		(void) fprintf(stderr, "%s: process not defunct: %d\n",
		    command, (int)pid);
		return (1);
	}

	*exit_status = psinfo.pr_wstat;
	*reap_pid = psinfo.pr_pid;
	ppid = psinfo.pr_ppid;

	if (ppid == 1) {
		(void) fprintf(stderr, "%s: Failed to reap %d: the only "
		    "non-defunct ancestor is 'init'\n", command,
		    (int)pid);
		return (1);
	}

	if (proc_usage(pid, &usage, &gret) == 0) {
		elapsed = usage.pr_tstamp.tv_sec - usage.pr_term.tv_sec;
	} else {
		(void) fprintf(stderr, "%s: cannot examine %d: %s\n",
		    command, (int)pid, Pgrab_error(gret));
		return (1);
	}

	if ((Fflag == 0) && (elapsed < NOREAP_TIME)) {
		(void) fprintf(stderr, "%s: unsafe to reap %d; it has been "
		    "defunct less than %d seconds\n", command, (int)pid,
		    NOREAP_TIME);
		return (1);
	}

	if ((Pr = Pgrab(ppid, Fflag | PGRAB_NOSTOP, &gret)) == NULL) {
		(void) fprintf(stderr, "%s: cannot examine %d: %s\n", command,
		    (int)ppid, Pgrab_error(gret));
		return (1);
	}

	if ((Fflag == 0) && (Pstate(Pr) == PS_STOP)) {
		Prelease(Pr, 0);
		(void) fprintf(stderr, "%s: unsafe to reap %d; parent is "
		    "stopped and may reap status upon restart\n", command,
		    (int)pid);
		return (1);
	}

	/*
	 * Pstop() will fail if the process to be stopped has become a zombie.
	 * This means that we can say with certainty that the child of this
	 * process has not changed parents (i.e. been reparented to init) once
	 * the Pstop() succeeds.
	 */
	if (Pstop(Pr, 1000) != 0) {
		Prelease(Pr, 0);
		(void) fprintf(stderr, "%s: failed to stop %d: %s", command,
		    (int)ppid, strerror(errno));
		return (1);
	}

	if (pr_waitid(Pr, P_PID, pid, &siginfo, WEXITED|WNOHANG) != 0) {
		Prelease(Pr, 0);
		(void) fprintf(stderr, "%s: waitid() in process %d failed: %s",
		    command, (int)ppid, strerror(errno));
		return (1);
	}

	Prelease(Pr, 0);
	return (0);
}

static void
print_exit_status(pid_t pid, int wstat)
{
	(void) printf("%d: ", (int)pid);
	if (WIFSIGNALED(wstat)) {
		char buf[SIG2STR_MAX];
		int sig = WTERMSIG(wstat);

		if (sig2str(sig, buf) == 0)
			(void) printf("killed by signal %s", buf);
		else
			(void) printf("killed by signal %d", sig);

		if (WCOREDUMP(wstat))
			(void) printf(" (core dumped)");
	} else {
		(void) printf("exited with status %d", WEXITSTATUS(wstat));
	}
	(void) printf("\n");
}

int
main(int argc, char *argv[])
{
	int retc = 0;
	int opt;
	int errflg = 0;

	if ((command = strrchr(argv[0], '/')) != NULL)
		command++;
	else
		command = argv[0];

	while ((opt = getopt(argc, argv, "F")) != EOF) {
		switch (opt) {
		case 'F':		/* force grabbing (no O_EXCL) */
			Fflag = PGRAB_FORCE;
			break;
		default:
			errflg = 1;
			break;
		}
	}

	argc -= optind;
	argv += optind;

	if (errflg || argc <= 0) {
		(void) fprintf(stderr, "usage:  %s pid ...\n", command);
		(void) fprintf(stderr, "  (Reap a defunct process by forcing "
		    "its parent to wait(2) for it)\n");
		exit(2);
	}

	/* catch signals from terminal */
	if (sigset(SIGHUP, SIG_IGN) == SIG_DFL)
		(void) sigset(SIGHUP, intr);
	if (sigset(SIGINT, SIG_IGN) == SIG_DFL)
		(void) sigset(SIGINT, intr);
	if (sigset(SIGPIPE, SIG_IGN) == SIG_DFL)
		(void) sigset(SIGPIPE, intr);
	if (sigset(SIGQUIT, SIG_IGN) == SIG_DFL)
		(void) sigset(SIGQUIT, intr);
	(void) sigset(SIGTERM, intr);

	while (--argc >= 0 && !interrupt) {
		pid_t pid;
		int wstat, r;

		retc += r = reap(*argv++, &pid, &wstat);

		if (r == 0)
			print_exit_status(pid, wstat);
	}

	if (interrupt && retc == 0)
		retc++;
	return (retc == 0 ? 0 : 1);
}
