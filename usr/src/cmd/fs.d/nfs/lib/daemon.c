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

/* LINTLIBRARY */
/* PROTOLIB1 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/* NFS server */

#include <sys/param.h>
#include <sys/types.h>
#include <errno.h>
#include <stdio.h>
#include <stdio_ext.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <libscf.h>

/*
 * The parent never returns from this function. It sits
 * and waits for the child to send status on whether it
 * loaded or not.
 *
 * We do not close down the standard file descriptors until
 * we know the child is going to run.
 */
int
daemonize_init(void)
{
	int status, pfds[2];
	sigset_t set, oset;
	pid_t pid;

	/*
	 * Block all signals prior to the fork and leave them blocked in the
	 * parent so we don't get in a situation where the parent gets SIGINT
	 * and returns non-zero exit status and the child is actually running.
	 * In the child, restore the signal mask once we've done our setsid().
	 */
	(void) sigfillset(&set);
	(void) sigdelset(&set, SIGABRT);
	(void) sigprocmask(SIG_BLOCK, &set, &oset);

	/*
	 * We need to do this before we open the pipe - it makes things
	 * easier in the long run.
	 */
	closefrom(STDERR_FILENO + 1);

	if (pipe(pfds) == -1) {
		fprintf(stderr, "failed to create pipe for daemonize");
		exit(SMF_EXIT_ERR_FATAL);
	}

	if ((pid = fork()) == -1) {
		fprintf(stderr, "failed to fork into background");
		exit(SMF_EXIT_ERR_FATAL);
	}

	if (pid != 0) {
		(void) close(pfds[1]);

		if (read(pfds[0], &status, sizeof (status)) == sizeof (status))
			exit(status);

		if (waitpid(pid, &status, 0) == pid && WIFEXITED(status))
			exit(WEXITSTATUS(status));

		exit(SMF_EXIT_ERR_FATAL);
	}

	/*
	 * All child from here on...
	 */
	(void) setsid();
	(void) sigprocmask(SIG_SETMASK, &oset, NULL);
	(void) close(pfds[0]);

	return (pfds[1]);
}

/*
 * We are only a daemon if the file descriptor is valid.
 */
void
daemonize_fini(int fd)
{
	int	status = 0;

	if (fd != -1) {
		(void) write(fd, &status, sizeof (status));

		(void) close(fd);

		if ((fd = open("/dev/null", O_RDWR)) >= 0) {
			(void) fcntl(fd, F_DUP2FD, STDIN_FILENO);
			(void) fcntl(fd, F_DUP2FD, STDOUT_FILENO);
			(void) fcntl(fd, F_DUP2FD, STDERR_FILENO);
			(void) close(fd);
		}
	}
}
