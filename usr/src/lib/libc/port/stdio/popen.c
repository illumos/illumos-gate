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

#pragma weak _pclose = pclose
#pragma weak _popen = popen

#include "lint.h"
#include "mtlib.h"
#include "file64.h"
#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <wait.h>
#include <signal.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <thread.h>
#include <pthread.h>
#include <synch.h>
#include <spawn.h>
#include "stdiom.h"
#include "mse.h"
#include "libc.h"

#define	tst(a, b) (*mode == 'r'? (b) : (a))
#define	RDR	0
#define	WTR	1

extern	int __xpg4;	/* defined in _xpg4.c; 0 if not xpg4-compiled program */
extern const char **environ;

static mutex_t popen_lock = DEFAULTMUTEX;

typedef struct node {
	pid_t	pid;
	int	fd;
	struct	node	*next;
} node_t;

static	node_t  *head = NULL;
static	void	_insert_nolock(pid_t, int, node_t *);

/*
 * Cancellation cleanup handler.
 * If we were cancelled in waitpid(), create a daemon thread to
 * reap our abandoned child.  No other thread can do this for us.
 */
static void
cleanup(void *arg)
{
	extern const sigset_t maskset;
	extern void *reapchild(void *);		/* see port/stdio/system.c */

	/*
	 * We have been cancelled.  There is no need to restore
	 * the original sigmask after blocking all signals because
	 * pthread_exit() will block all signals while we exit.
	 */
	(void) thr_sigsetmask(SIG_SETMASK, &maskset, NULL);
	(void) thr_create(NULL, 0, reapchild, arg, THR_DAEMON, NULL);
}

FILE *
popen(const char *cmd, const char *mode)
{
	int	p[2];
	pid_t	pid;
	int	myside;
	int	yourside;
	int	fd;
	const char *shpath;
	FILE	*iop;
	int	stdio;
	node_t	*curr;
	char	*argvec[4];
	node_t	*node;
	posix_spawnattr_t attr;
	posix_spawn_file_actions_t fact;
	int	error;
	static const char *sun_path = "/bin/sh";
	static const char *xpg4_path = "/usr/xpg4/bin/sh";
	static const char *shell = "sh";
	static const char *sh_flg = "-c";

	if ((node = lmalloc(sizeof (node_t))) == NULL)
		return (NULL);
	if ((error = posix_spawnattr_init(&attr)) != 0) {
		lfree(node, sizeof (node_t));
		errno = error;
		return (NULL);
	}
	if ((error = posix_spawn_file_actions_init(&fact)) != 0) {
		lfree(node, sizeof (node_t));
		(void) posix_spawnattr_destroy(&attr);
		errno = error;
		return (NULL);
	}
	if (pipe(p) < 0) {
		error = errno;
		lfree(node, sizeof (node_t));
		(void) posix_spawnattr_destroy(&attr);
		(void) posix_spawn_file_actions_destroy(&fact);
		errno = error;
		return (NULL);
	}

	shpath = __xpg4? xpg4_path : sun_path;
	if (access(shpath, X_OK))	/* XPG4 Requirement: */
		shpath = "";		/* force child to fail immediately */

	myside = tst(p[WTR], p[RDR]);
	yourside = tst(p[RDR], p[WTR]);
	/* myside and yourside reverse roles in child */
	stdio = tst(0, 1);

	/* This will fail more quickly if we run out of fds */
	if ((iop = fdopen(myside, mode)) == NULL) {
		error = errno;
		lfree(node, sizeof (node_t));
		(void) posix_spawnattr_destroy(&attr);
		(void) posix_spawn_file_actions_destroy(&fact);
		(void) close(yourside);
		(void) close(myside);
		errno = error;
		return (NULL);
	}

	lmutex_lock(&popen_lock);

	/* in the child, close all pipes from other popen's */
	for (curr = head; curr != NULL && error == 0; curr = curr->next) {
		/*
		 * These conditions may apply if a previous iob returned
		 * by popen() was closed with fclose() rather than pclose(),
		 * or if close(fileno(iob)) was called.  Don't let these
		 * programming errors cause us to malfunction here.
		 */
		if ((fd = curr->fd) != myside && fd != yourside &&
		    fcntl(fd, F_GETFD) >= 0)
			error = posix_spawn_file_actions_addclose(&fact, fd);
	}
	if (error == 0)
		error =  posix_spawn_file_actions_addclose(&fact, myside);
	if (yourside != stdio) {
		if (error == 0)
			error = posix_spawn_file_actions_adddup2(&fact,
			    yourside, stdio);
		if (error == 0)
			error = posix_spawn_file_actions_addclose(&fact,
			    yourside);
	}
	if (error == 0)
		error = posix_spawnattr_setflags(&attr,
		    POSIX_SPAWN_NOSIGCHLD_NP | POSIX_SPAWN_WAITPID_NP);
	if (error) {
		lmutex_unlock(&popen_lock);
		lfree(node, sizeof (node_t));
		(void) posix_spawnattr_destroy(&attr);
		(void) posix_spawn_file_actions_destroy(&fact);
		(void) fclose(iop);
		(void) close(yourside);
		errno = error;
		return (NULL);
	}
	argvec[0] = (char *)shell;
	argvec[1] = (char *)sh_flg;
	argvec[2] = (char *)cmd;
	argvec[3] = NULL;
	error = posix_spawn(&pid, shpath, &fact, &attr,
	    (char *const *)argvec, (char *const *)environ);
	(void) posix_spawnattr_destroy(&attr);
	(void) posix_spawn_file_actions_destroy(&fact);
	(void) close(yourside);
	if (error) {
		lmutex_unlock(&popen_lock);
		lfree(node, sizeof (node_t));
		(void) fclose(iop);
		errno = error;
		return (NULL);
	}
	_insert_nolock(pid, myside, node);

	lmutex_unlock(&popen_lock);

	_SET_ORIENTATION_BYTE(iop);

	return (iop);
}

/*
 * pclose() is a cancellation point.
 */
int
pclose(FILE *ptr)
{
	pid_t	pid;
	int status;

	pid = _delete(fileno(ptr));

	/* mark this pipe closed */
	(void) fclose(ptr);

	if (pid <= 0) {
		errno = ECHILD;
		return (-1);
	}

	/*
	 * waitpid() is a cancellation point.
	 * This causes pclose() to be a cancellation point.
	 *
	 * If we have already been cancelled (pclose() was called from
	 * a cancellation cleanup handler), attempt to reap the process
	 * w/o waiting, and if that fails just call cleanup(pid).
	 */

	if (_thrp_cancelled()) {
		/* waitpid(..., WNOHANG) is not a cancellation point */
		if (waitpid(pid, &status, WNOHANG) == pid)
			return (status);
		cleanup((void *)(uintptr_t)pid);
		errno = ECHILD;
		return (-1);
	}

	pthread_cleanup_push(cleanup, (void *)(uintptr_t)pid);
	while (waitpid(pid, &status, 0) < 0) {
		if (errno != EINTR) {
			status = -1;
			break;
		}
	}
	pthread_cleanup_pop(0);

	return (status);
}


static void
_insert_nolock(pid_t pid, int fd, node_t *new)
{
	node_t	*prev;
	node_t	*curr;

	for (prev = curr = head; curr != NULL; curr = curr->next) {
		/*
		 * curr->fd can equal fd if a previous iob returned by
		 * popen() was closed with fclose() rather than pclose(),
		 * or if close(fileno(iob)) was called.  Don't let these
		 * programming errors cause us to malfunction here.
		 */
		if (curr->fd == fd) {
			/* make a lame attempt to reap the forgotten child */
			(void) waitpid(curr->pid, NULL, WNOHANG);
			curr->pid = pid;
			lfree(new, sizeof (node_t));
			return;
		}
		prev = curr;
	}

	new->pid = pid;
	new->fd = fd;
	new->next = NULL;

	if (head == NULL)
		head = new;
	else
		prev->next = new;
}

/*
 * _insert() and _delete() are used by p2open() in libgen.
 */
int
_insert(pid_t pid, int fd)
{
	node_t *node;

	if ((node = lmalloc(sizeof (node_t))) == NULL)
		return (-1);

	lmutex_lock(&popen_lock);
	_insert_nolock(pid, fd, node);
	lmutex_unlock(&popen_lock);

	return (0);
}


pid_t
_delete(int fd)
{
	node_t	*prev;
	node_t	*curr;
	pid_t	pid;

	lmutex_lock(&popen_lock);

	for (prev = curr = head; curr != NULL; curr = curr->next) {
		if (curr->fd == fd) {
			if (curr == head)
				head = curr->next;
			else
				prev->next = curr->next;
			lmutex_unlock(&popen_lock);
			pid = curr->pid;
			lfree(curr, sizeof (node_t));
			return (pid);
		}
		prev = curr;
	}

	lmutex_unlock(&popen_lock);

	return (-1);
}
