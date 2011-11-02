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

/*
 * Copyright (c) 2011 by Delphix. All rights reserved.
 */

/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved  	*/

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
#include <paths.h>
#include "stdiom.h"
#include "mse.h"
#include "libc.h"

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
	pid_t	pid;
	int	myfd, fd;
	const char *shpath = _PATH_BSHELL;
	FILE	*iop;
	node_t	*curr;
	node_t	*node;
	posix_spawn_file_actions_t fact;
	posix_spawnattr_t attr;
	int	error;

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

	if (access(shpath, X_OK))	/* XPG4 Requirement: */
		shpath = "";		/* force child to fail immediately */


	/*
	 * fdopen() can fail (if the fd is too high or we are out of memory),
	 * but we don't want to have any way to fail after creating the child
	 * process.  So we fdopen() a dummy fd (myfd), and once we get the real
	 * fd from posix_spawn_pipe_np(), we dup2() the real fd onto the dummy.
	 */
	myfd = open("/dev/null", O_RDWR);
	if (myfd == -1) {
		error = errno;
		lfree(node, sizeof (node_t));
		(void) posix_spawnattr_destroy(&attr);
		(void) posix_spawn_file_actions_destroy(&fact);
		errno = error;
		return (NULL);
	}
	iop = fdopen(myfd, mode);
	if (iop == NULL) {
		error = errno;
		lfree(node, sizeof (node_t));
		(void) posix_spawnattr_destroy(&attr);
		(void) posix_spawn_file_actions_destroy(&fact);
		(void) close(myfd);
		errno = error;
		return (NULL);
	}

	lmutex_lock(&popen_lock);

	/* in the child, close all pipes from other popen's */
	for (curr = head; curr != NULL && error == 0; curr = curr->next) {
		/*
		 * The fd may no longer be open if an iob previously returned
		 * by popen() was closed with fclose() rather than pclose(),
		 * or if close(fileno(iob)) was called.  Use fcntl() to check
		 * if the fd is still open, so that these programming errors
		 * won't cause us to malfunction here.
		 */
		if (fcntl(curr->fd, F_GETFD) >= 0) {
			error = posix_spawn_file_actions_addclose(&fact,
			    curr->fd);
		}
	}
	/*
	 * See the comments in port/stdio/system.c for why these
	 * non-portable posix_spawn() attributes are being used.
	 */
	if (error == 0) {
		error = posix_spawnattr_setflags(&attr,
		    POSIX_SPAWN_NOSIGCHLD_NP |
		    POSIX_SPAWN_WAITPID_NP |
		    POSIX_SPAWN_NOEXECERR_NP);
	}
	if (error != 0) {
		lmutex_unlock(&popen_lock);
		lfree(node, sizeof (node_t));
		(void) posix_spawnattr_destroy(&attr);
		(void) posix_spawn_file_actions_destroy(&fact);
		(void) fclose(iop);
		errno = error;
		return (NULL);
	}
	error = posix_spawn_pipe_np(&pid, &fd, cmd, *mode != 'r', &fact, &attr);
	(void) posix_spawnattr_destroy(&attr);
	(void) posix_spawn_file_actions_destroy(&fact);
	if (error != 0) {
		lmutex_unlock(&popen_lock);
		lfree(node, sizeof (node_t));
		(void) fclose(iop);
		errno = error;
		return (NULL);
	}
	_insert_nolock(pid, myfd, node);

	lmutex_unlock(&popen_lock);

	/*
	 * myfd is the one that we fdopen()'ed; make it refer to the
	 * pipe to the child.
	 */
	(void) dup2(fd, myfd);
	(void) close(fd);

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
