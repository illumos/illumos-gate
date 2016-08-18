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
 * Copyright 2016 Joyent, Inc.
 */

/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved  	*/

#include "lint.h"
#include "mtlib.h"
#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>
#include <stdlib.h>
#include <wait.h>
#include <sys/stat.h>
#include <unistd.h>
#include <memory.h>
#include <thread.h>
#include <pthread.h>
#include <errno.h>
#include <synch.h>
#include <spawn.h>
#include <paths.h>
#include <zone.h>
#include "libc.h"

extern const char **_environ;

extern int __xpg4;	/* defined in _xpg4.c; 0 if not xpg4-compiled program */
extern const sigset_t maskset;		/* all maskable signals */

static mutex_t sys_lock = DEFAULTMUTEX;	/* protects the following */
static uint_t sys_count = 0;		/* number of threads in system() */
static struct sigaction sys_ibuf;	/* saved SIGINT sigaction */
static struct sigaction sys_qbuf;	/* saved SIGQUIT sigaction */
static struct sigaction ignore = {0, {SIG_IGN}, {0}};

/*
 * Things needed by the cancellation cleanup handler.
 */
typedef struct {
	sigset_t	savemask;	/* saved signal mask */
	pid_t		pid;		/* if nonzero, the child's pid */
} cleanup_t;

/*
 * Daemon thread whose sole function is to reap an abandoned child.
 * Also invoked from pclose() (see port/stdio/popen.c).
 */
void *
reapchild(void *arg)
{
	pid_t pid = (pid_t)(uintptr_t)arg;
	int cancel_state;

	(void) pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &cancel_state);
	while (waitpid(pid, NULL, 0) == -1) {
		if (errno != EINTR)
			break;
	}
	(void) pthread_setcancelstate(cancel_state, NULL);
	return (NULL);
}

/*
 * Cancellation cleanup handler.
 * If we were cancelled in waitpid(), create a daemon thread to
 * reap our abandoned child.  No other thread can do this for us.
 * It would be better if there were a system call to disinherit
 * a child process (give it to init, just as though we exited).
 */
static void
cleanup(void *arg)
{
	cleanup_t *cup = arg;

	if (cup->pid != 0) {	/* we were cancelled; abandoning our pid */
		(void) thr_sigsetmask(SIG_SETMASK, &maskset, NULL);
		(void) thr_create(NULL, 0,
		    reapchild, (void *)(uintptr_t)cup->pid,
		    THR_DAEMON, NULL);
	}

	lmutex_lock(&sys_lock);
	if (--sys_count == 0) {		/* leaving system() */
		/*
		 * There are no remaining threads in system(), so
		 * restore the SIGINT and SIGQUIT signal actions.
		 */
		(void) sigaction(SIGINT, &sys_ibuf, NULL);
		(void) sigaction(SIGQUIT, &sys_qbuf, NULL);
	}
	lmutex_unlock(&sys_lock);

	(void) thr_sigsetmask(SIG_SETMASK, &cup->savemask, NULL);
}

int
system(const char *cmd)
{
	cleanup_t cu;
	pid_t w;
	int status;
	int error;
	sigset_t mask;
	struct stat64 buf;
	char shpath[MAXPATHLEN];
	const char *zroot = zone_get_nroot();
	char *argv[4];
	posix_spawnattr_t attr;
	static const char *shell = "sh";

	/*
	 * If executing in brand use native root.
	 */
	(void) snprintf(shpath, sizeof (shpath), "%s%s",
	    zroot != NULL ? zroot : "", _PATH_BSHELL);

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
	 *
	 * The setting of POSIX_SPAWN_WAITPID_NP ensures that no
	 * wait-for-multiple wait() operation will reap our child
	 * and that the child will not be automatically reaped due
	 * to the disposition of SIGCHLD being set to be ignored.
	 * Only a specific wait for the specific pid will be able
	 * to reap the child.  Since no other thread knows the pid
	 * of our child, this should be safe enough.
	 *
	 * The POSIX_SPAWN_NOEXECERR_NP flag tells posix_spawn() not
	 * to fail if the shell cannot be executed, but rather cause
	 * a child to be created that simply performs _exit(127).
	 * This is in order to satisfy the Posix requirement on system():
	 *	The system function shall behave as if a child process were
	 *	created using fork(), and the child process invoked the sh
	 *	utility using execl().  If some error prevents the command
	 *	language interpreter from executing after the child process
	 *	is created, the return value from system() shall be as if
	 *	the command language interpreter had terminated using
	 *	exit(127) or _exit(127).
	 */
	error = posix_spawnattr_init(&attr);
	if (error == 0)
		error = posix_spawnattr_setflags(&attr,
		    POSIX_SPAWN_SETSIGMASK | POSIX_SPAWN_SETSIGDEF |
		    POSIX_SPAWN_NOSIGCHLD_NP | POSIX_SPAWN_WAITPID_NP |
		    POSIX_SPAWN_NOEXECERR_NP);

	/*
	 * The POSIX spec for system() requires us to block SIGCHLD,
	 * the rationale being that the process's signal handler for
	 * SIGCHLD, if any, should not be called when our child exits.
	 * This doesn't work for a multithreaded process because some
	 * other thread could receive the SIGCHLD.
	 *
	 * The above setting of POSIX_SPAWN_NOSIGCHLD_NP ensures that no
	 * SIGCHLD signal will be posted for our child when it exits, so
	 * we don't have to block SIGCHLD to meet the intent of the spec.
	 * We block SIGCHLD anyway, just because the spec requires it.
	 */
	(void) sigemptyset(&mask);
	(void) sigaddset(&mask, SIGCHLD);
	(void) thr_sigsetmask(SIG_BLOCK, &mask, &cu.savemask);
	/*
	 * Tell posix_spawn() to restore the signal mask in the child.
	 */
	if (error == 0)
		error = posix_spawnattr_setsigmask(&attr, &cu.savemask);

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
		(void) sigaction(SIGINT, &ignore, &sys_ibuf);
		(void) sigaction(SIGQUIT, &ignore, &sys_qbuf);
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

	argv[0] = (char *)shell;
	argv[1] = "-c";
	argv[2] = (char *)cmd;
	argv[3] = NULL;
	if (error == 0)
		error = posix_spawn(&cu.pid, shpath, NULL, &attr,
		    (char *const *)argv, (char *const *)_environ);

	(void) posix_spawnattr_destroy(&attr);

	if (error) {
		errno = error;
		status = -1;
	} else {
		/*
		 * system() is a cancellation point and so is waitpid().
		 */
		pthread_cleanup_push(cleanup, &cu);
		do {
			w = waitpid(cu.pid, &status, 0);
		} while (w == -1 && errno == EINTR);
		pthread_cleanup_pop(0);
		if (w == -1)
			status = -1;
	}
	error = errno;
	cu.pid = 0;
	cleanup(&cu);
	errno = error;

	return (status);
}
