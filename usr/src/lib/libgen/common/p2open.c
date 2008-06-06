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
 * Similar to popen(3S) but with pipe to cmd's stdin and from stdout.
 */

#include <sys/types.h>
#include <libgen.h>
#include <stdio.h>
#include <signal.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/wait.h>
#include <errno.h>
#include "lib_gen.h"

/* functions in libc */
extern int _insert(pid_t pid, int fd);
extern pid_t _delete(int fd);

int
p2open(const char *cmd, FILE *fp[2])
{
	int	fds[2];

	if (__p2open(cmd, fds) == -1)
		return (-1);

	fp[0] = fdopen(fds[0], "w");
	fp[1] = fdopen(fds[1], "r");
	return (0);
}

int
p2close(FILE *fp[2])
{
	return (__p2close(NULL, fp, 0));
}

int
__p2open(const char *cmd, int fds[2])
{
	int	tocmd[2];
	int	fromcmd[2];
	pid_t	pid;

	if (pipe(tocmd) < 0 || pipe(fromcmd) < 0)
		return (-1);
#ifndef _LP64
	if (tocmd[1] >= 256 || fromcmd[0] >= 256) {
		(void) close(tocmd[0]);
		(void) close(tocmd[1]);
		(void) close(fromcmd[0]);
		(void) close(fromcmd[1]);
		return (-1);
	}
#endif	/*	_LP64	*/
	if ((pid = fork()) == 0) {
		(void) close(tocmd[1]);
		(void) close(0);
		(void) fcntl(tocmd[0], F_DUPFD, 0);
		(void) close(tocmd[0]);
		(void) close(fromcmd[0]);
		(void) close(1);
		(void) fcntl(fromcmd[1], F_DUPFD, 1);
		(void) close(fromcmd[1]);
		(void) execl("/bin/sh", "sh", "-c", cmd, 0);
		_exit(1);
	}
	if (pid == (pid_t)-1)
		return (-1);
	(void) _insert(pid, tocmd[1]);
	(void) _insert(pid, fromcmd[0]);
	(void) close(tocmd[0]);
	(void) close(fromcmd[1]);
	fds[0] = tocmd[1];
	fds[1] = fromcmd[0];
	return (0);
}

int
__p2close(int *fdp, FILE **fpp, int kill_sig)
{
	int		fds[2];
	int		status;
	void		(*hstat)(int), (*istat)(int), (*qstat)(int);
	pid_t pid, r;

	if (fdp != NULL) {
		fds[0] = fdp[0];
		fds[1] = fdp[1];
	} else if (fpp != NULL) {
		fds[0] = fileno(fpp[0]);
		fds[1] = fileno(fpp[1]);
	} else {
		return (-1);
	}

	pid = _delete(fds[0]);
	if (pid != _delete(fds[1]))
		return (-1);

	if (pid == (pid_t)-1)
		return (-1);

	if (kill_sig != 0) {
		(void) kill(pid, kill_sig);
	}

	if (fdp != NULL) {
		(void) close(fds[0]);
		(void) close(fds[1]);
	} else {
		(void) fclose(fpp[0]);
		(void) fclose(fpp[1]);
	}

	istat = signal(SIGINT, SIG_IGN);
	qstat = signal(SIGQUIT, SIG_IGN);
	hstat = signal(SIGHUP, SIG_IGN);
	while ((r = waitpid(pid, &status, 0)) == (pid_t)-1 && errno == EINTR)
		;
	if (r == (pid_t)-1)
		status = -1;
	(void) signal(SIGINT, istat);
	(void) signal(SIGQUIT, qstat);
	(void) signal(SIGHUP, hstat);
	return (status);
}
