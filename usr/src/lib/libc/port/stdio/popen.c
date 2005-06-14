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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved  	*/


#pragma weak pclose = _pclose
#pragma weak popen = _popen

#include "synonyms.h"
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
#include <synch.h>
#include <spawn.h>
#include "stdiom.h"
#include "mse.h"
#include "libc.h"

#define	tst(a, b) (*mode == 'r'? (b) : (a))
#define	RDR	0
#define	WTR	1

#ifndef	_LP64
#define	MAX_FD (1 << (NBBY * (unsigned)sizeof (_lastbuf->_file))) /* now 256 */
#endif	/*	_LP64	*/

static int _insert_nolock(pid_t, int);

extern	int __xpg4;	/* defined in _xpg4.c; 0 if not xpg4-compiled program */
extern const char **environ;

static mutex_t popen_lock = DEFAULTMUTEX;

typedef struct node {
	pid_t	pid;
	int	fd;
	struct	node	*next;
} node_t;

static	node_t  *head = NULL;


FILE *
popen(const char *cmd, const char *mode)
{
	int	p[2];
	pid_t	pid;
	int	myside, yourside;
	const char *shpath;
	FILE	*iop;
	int	stdio;
	node_t	*curr;
	char	*argvec[4];
	posix_spawn_file_actions_t fact;
	int	error;
	static const char *sun_path = "/bin/sh";
	static const char *xpg4_path = "/usr/xpg4/bin/sh";
	static const char *shell = "sh";
	static const char *sh_flg = "-c";

	if (pipe(p) < 0)
		return (NULL);

#ifndef	_LP64
	/* check that the fd's are in range for a struct FILE */
	if ((p[WTR] >= MAX_FD) || (p[RDR] >= MAX_FD)) {
		(void) close(p[WTR]);
		(void) close(p[RDR]);
		errno = EMFILE;
		return (NULL);
	}
#endif	/* _LP64 */

	shpath = __xpg4? xpg4_path : sun_path;
	if (access(shpath, X_OK))	/* XPG4 Requirement: */
		shpath = "";		/* force child to fail immediately */

	myside = tst(p[WTR], p[RDR]);
	yourside = tst(p[RDR], p[WTR]);
	/* myside and yourside reverse roles in child */
	stdio = tst(0, 1);

	lmutex_lock(&popen_lock);

	/* in the child, close all pipes from other popen's */
	if ((error = posix_spawn_file_actions_init(&fact)) != 0) {
		lmutex_unlock(&popen_lock);
		(void) close(myside);
		(void) close(yourside);
		errno = error;
		return (NULL);
	}
	for (curr = head; curr != NULL && error == 0; curr = curr->next)
		error = posix_spawn_file_actions_addclose(&fact, curr->fd);
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
	if (error) {
		lmutex_unlock(&popen_lock);
		(void) posix_spawn_file_actions_destroy(&fact);
		(void) close(myside);
		(void) close(yourside);
		errno = error;
		return (NULL);
	}
	argvec[0] = (char *)shell;
	argvec[1] = (char *)sh_flg;
	argvec[2] = (char *)cmd;
	argvec[3] = NULL;
	error = posix_spawn(&pid, shpath, &fact, NULL,
		(char *const *)argvec, (char *const *)environ);
	(void) posix_spawn_file_actions_destroy(&fact);

	(void) close(yourside);
	if ((errno = error) != 0 || _insert_nolock(pid, myside) == -1) {
		lmutex_unlock(&popen_lock);
		(void) close(myside);
		return (NULL);
	}

	lmutex_unlock(&popen_lock);

	if ((iop = fdopen(myside, mode)) == NULL) {
		(void) _delete(myside);
		(void) close(myside);
		return (NULL);
	}
	_SET_ORIENTATION_BYTE(iop);

	return (iop);
}

int
pclose(FILE *ptr)
{
	pid_t	pid;
	int status;

	pid = _delete(fileno(ptr));

	/* mark this pipe closed */
	(void) fclose(ptr);

	if (pid == -1)
		return (-1);

	while (waitpid(pid, &status, 0) < 0) {
		/* If waitpid fails with EINTR, restart the waitpid call */
		if (errno != EINTR) {
			status = -1;
			break;
		}
	}

	return (status);
}


static int
_insert_nolock(pid_t pid, int fd)
{
	node_t	*prev;
	node_t	*curr;
	node_t	*new;

	for (prev = curr = head; curr != NULL; curr = curr->next)
		prev = curr;

	if ((new = lmalloc(sizeof (node_t))) == NULL)
		return (-1);

	new->pid = pid;
	new->fd = fd;
	new->next = NULL;

	if (head == NULL)
		head = new;
	else
		prev->next = new;

	return (0);
}

/*
 * _insert() and _delete() are used by p2open() in libgen.
 */
int
_insert(pid_t pid, int fd)
{
	int rc;

	lmutex_lock(&popen_lock);
	rc = _insert_nolock(pid, fd);
	lmutex_unlock(&popen_lock);

	return (rc);
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

			pid = curr->pid;
			lfree(curr, sizeof (node_t));
			lmutex_unlock(&popen_lock);
			return (pid);
		}
		prev = curr;
	}

	lmutex_unlock(&popen_lock);

	return (-1);
}
