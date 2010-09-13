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
/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved  	*/


/*
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 *	cscope - interactive C symbol cross-reference
 *
 *	process execution functions
 */

#include "global.h"
#include <sys/types.h>
#include <sys/wait.h>
#include <stdarg.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <libgen.h>

#define	getdtablesize()	_NFILE

#define	MAXARGS	100	/* maximum number of arguments to executed command */

pid_t	childpid;	/* child's process ID */

static	SIGTYPE	(*oldsigquit)();	/* old value of quit signal */
static	SIGTYPE	(*oldsigtstp)();	/* old value of terminal stop signal */

static pid_t myfork(void);
static int join(pid_t p);

/*
 * execute forks and executes a program or shell script, waits for it to
 * finish, and returns its exit code.
 */

/*VARARGS0*/
int
execute(char *path, ...)
{
	va_list	ap;
	char	*args[MAXARGS + 1];
	int	exitcode;
	int	i;
	char	msg[MSGLEN + 1];
	pid_t	p;

	/* fork and exec the program or shell script */
	exitcurses();
	if ((p = myfork()) == 0) {

		/* close all files except stdin, stdout, and stderr */
		for (i = 3; i < getdtablesize() && close(i) == 0; ++i) {
			;
		}
		/* execute the program or shell script */
		va_start(ap, path);
		for (i = 0; i < MAXARGS &&
		    (args[i] = va_arg(ap, char *)) != NULL; ++i) {
		}
		va_end(ap);
		args[i] = NULL;			/* in case MAXARGS reached */
		args[0] = basename(args[0]);
		(void) execvp(path, args);	/* returns only on failure */
		(void) sprintf(msg, "\ncscope: cannot execute %s", path);
		(void) perror(msg);	/* display the reason */
		askforreturn();	 /* wait until the user sees the message */
		exit(1);		/* exit the child */
	} else {
		exitcode = join(p);	/* parent */
	}
	if (noacttimeout) {
		(void) fprintf(stderr,
		    "cscope: no activity time out--exiting\n");
		myexit(SIGALRM);
	}
	entercurses();
	return (exitcode);
}

/* myfork acts like fork but also handles signals */

static pid_t
myfork(void)
{
	pid_t	p;		/* process number */

	oldsigtstp = signal(SIGTSTP, SIG_DFL);
	/* the parent ignores the interrupt and quit signals */
	if ((p = fork()) > 0) {
		childpid = p;
		oldsigquit = signal(SIGQUIT, SIG_IGN);
	}
	/* so they can be used to stop the child */
	else if (p == 0) {
		(void) signal(SIGINT, SIG_DFL);
		(void) signal(SIGQUIT, SIG_DFL);
		(void) signal(SIGHUP, SIG_DFL);	/* restore hangup default */
	}
	/* check for fork failure */
	if (p == -1) {
		myperror("Cannot fork");
	}
	return (p);
}

/* join is the compliment of fork */

static int
join(pid_t p)
{
	int	status;
	pid_t	w;

	/* wait for the correct child to exit */
	do {
		w = wait(&status);
	} while (p != -1 && w != p);
	childpid = 0;

	/* restore signal handling */
	(void) signal(SIGQUIT, oldsigquit);
	(void) signal(SIGTSTP, oldsigtstp);
	/* return the child's exit code */
	return (status >> 8);
}
