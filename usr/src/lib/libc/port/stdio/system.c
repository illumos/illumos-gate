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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved  	*/


#include "synonyms.h"
#include "mtlib.h"
#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>
#include <stdlib.h>
#include <wait.h>
#include <sys/stat.h>
#include <unistd.h>
#include <memory.h>
#include <pthread.h>
#include <errno.h>
#include <synch.h>
#include <spawn.h>
#include "libc.h"

extern const char **environ;

extern int __xpg4;	/* defined in _xpg4.c; 0 if not xpg4-compiled program */

static mutex_t sys_lock = DEFAULTMUTEX;	/* protects the following */
static uint_t sys_count = 0;		/* number of threads in system() */
static struct sigaction sys_ibuf;	/* SIGINT */
static struct sigaction sys_qbuf;	/* SIGQUIT */
static struct sigaction sys_cbuf;	/* SIGCHLD */

/*
 * Cancellation cleanup handler.
 */
static void
cleanup(void *arg)
{
	sigset_t *savemaskp = arg;

	lmutex_lock(&sys_lock);
	if (--sys_count == 0) {		/* leaving system() */
		/*
		 * There are no remaining threads in system(),
		 * so restore the several signal actions.
		 */
		(void) sigaction(SIGINT, &sys_ibuf, NULL);
		(void) sigaction(SIGQUIT, &sys_qbuf, NULL);
		if (sys_cbuf.sa_handler == SIG_IGN ||
		    (sys_cbuf.sa_flags & SA_NOCLDWAIT))
			(void) sigaction(SIGCHLD, &sys_cbuf, NULL);
	}
	lmutex_unlock(&sys_lock);
	(void) sigprocmask(SIG_SETMASK, savemaskp, NULL);
}

int
system(const char *cmd)
{
	pid_t pid;
	pid_t w;
	int status;
	int error;
	struct sigaction action;
	sigset_t mask;
	sigset_t savemask;
	struct stat64 buf;
	const char *shpath;
	char *argvec[4];
	posix_spawnattr_t attr;
	static const char *sun_path = "/bin/sh";
	static const char *xpg4_path = "/usr/xpg4/bin/sh";
	static const char *shell = "sh";

	shpath = __xpg4? xpg4_path : sun_path;

	if (cmd == NULL) {
		if (stat64(shpath, &buf) != 0) {
			return (0);
		} else if (getuid() == buf.st_uid) {
			/* exec for user */
			if ((buf.st_mode & 0100) == 0)
				return (0);
		} else if (getgid() == buf.st_gid) {
			/* exec for group */
			if ((buf.st_mode & 0010) == 0)
				return (0);
		} else if ((buf.st_mode & 0001) == 0) {	/* exec for others */
			return (0);
		}
		return (1);
	}

	/*
	 * Initialize the posix_spawn() attributes structure.
	 */
	if ((error = posix_spawnattr_init(&attr)) != 0) {
		errno = error;
		return (-1);
	}
	error = posix_spawnattr_setflags(&attr,
	    POSIX_SPAWN_SETSIGMASK | POSIX_SPAWN_SETSIGDEF);

	/*
	 * We are required to block SIGCHLD so that we don't cause
	 * the process's signal handler, if any, to be called.
	 * This doesn't really work for a multithreaded process
	 * because some other thread may receive the SIGCHLD.
	 */
	(void) sigemptyset(&mask);
	(void) sigaddset(&mask, SIGCHLD);
	(void) sigprocmask(SIG_BLOCK, &mask, &savemask);
	/*
	 * Tell posix_spawn() to restore the signal mask in the child.
	 */
	if (error == 0)
		error = posix_spawnattr_setsigmask(&attr, &savemask);

	/*
	 * We are required to set the disposition of SIGINT and SIGQUIT
	 * to be ignored for the duration of the system() operation.
	 *
	 * We allow more than one thread to call system() concurrently by
	 * keeping a count of such threads.  The signal actions are set
	 * to SIG_IGN when the first thread calls system().  They are
	 * restored in cleanup() when the last thread exits system().
	 *
	 * However, system() is still MT-unsafe because sigaction() has
	 * a process-wide effect and some other thread may also be
	 * setting the signal actions for SIGINT or SIGQUIT.
	 */
	lmutex_lock(&sys_lock);
	if (sys_count++ == 0) {
		(void) memset(&action, 0, sizeof (action));
		action.sa_handler = SIG_IGN;
		(void) sigaction(SIGINT, &action, &sys_ibuf);
		(void) sigaction(SIGQUIT, &action, &sys_qbuf);
		/*
		 * If the action for SIGCHLD is SIG_IGN, then set it to SIG_DFL
		 * so we can retrieve the status of the spawned-off shell.
		 * The execve() performed in posix_spawn() will set the action
		 * for SIGCHLD in the child process to SIG_DFL regardless,
		 * so this has no negative consequencies for the child.
		 *
		 * Note that this is not required by the SUSv3 standard.
		 * The standard permits this error:
		 *	ECHILD	The status of the child process created
		 *		by system() is no longer available.
		 * So we could leave the action for SIGCHLD alone and
		 * still be standards-conforming, but this is the way
		 * the SunOS system() has always behaved (in fact it
		 * used to set the action to SIG_DFL unconditinally),
		 * so we retain this behavior here.
		 */
		(void) sigaction(SIGCHLD, NULL, &sys_cbuf);
		if (sys_cbuf.sa_handler == SIG_IGN ||
		    (sys_cbuf.sa_flags & SA_NOCLDWAIT)) {
			action.sa_handler = SIG_DFL;
			(void) sigaction(SIGCHLD, &action, NULL);
		}
	}
	lmutex_unlock(&sys_lock);

	/*
	 * If SIGINT and SIGQUIT were not already SIG_IGN, tell
	 * posix_spawn() to make them SIG_DFL in the child,
	 * else leave them as SIG_IGN in the child.
	 */
	(void) sigemptyset(&mask);
	if (sys_ibuf.sa_handler != SIG_IGN)
		(void) sigaddset(&mask, SIGINT);
	if (sys_qbuf.sa_handler != SIG_IGN)
		(void) sigaddset(&mask, SIGQUIT);
	if (error == 0)
		error = posix_spawnattr_setsigdefault(&attr, &mask);

	argvec[0] = (char *)shell;
	argvec[1] = "-c";
	argvec[2] = (char *)cmd;
	argvec[3] = NULL;
	if (error == 0)
		error = posix_spawn(&pid, shpath, NULL, &attr,
			(char *const *)argvec, (char *const *)environ);

	(void) posix_spawnattr_destroy(&attr);

	if (error) {
		errno = error;
		status = -1;
	} else {
		/*
		 * system() is a cancellation point.
		 * Call waitpid_cancel() rather than _waitpid() to make
		 * sure that we actually perform the cancellation logic.
		 */
		pthread_cleanup_push(cleanup, &savemask);
		do {
			w = waitpid_cancel(pid, &status, 0);
		} while (w == -1 && errno == EINTR);
		pthread_cleanup_pop(0);
		if (w == -1)
			status = -1;
	}
	cleanup(&savemask);

	return (status);
}
