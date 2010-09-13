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
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


/*
 * University Copyright- Copyright (c) 1982, 1986, 1988
 * The Regents of the University of California
 * All Rights Reserved
 *
 * University Acknowledgment- Portions of this document are derived from
 * software developed by the University of California, Berkeley, and its
 * contributors.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * mailx -- a modified version of a University of California at Berkeley
 *	mail program
 *
 * npopen() and npclose()
 *
 * stolen from C library, modified to use SHELL variable
 */


#include <stdio.h>
#include <signal.h>
#include <fcntl.h>

#define	tst(a,b) (*mode == 'r'? (b) : (a))
#define	RDR	0
#define	WTR	1

#ifdef VMUNIX
#define	sigset	signal
#else
extern void (*sigset())();
#endif
#ifdef preSVr4
extern FILE *fdopen();
extern int execlp(), fork(), pipe(), close(), fcntl();
#ifndef sun
typedef int pid_t;
#endif
#else
# include <unistd.h>
# include <wait.h>
#endif
static pid_t popen_pid[20];

FILE *
npopen(char *cmd, char *mode)
{
	int	p[2];
	register pid_t pid;
	register int myside, yourside;
	char *Shell, *value(char *);

	if ((Shell = value("SHELL")) == NULL || *Shell=='\0')
#ifdef preSVr4
		Shell = "/bin/sh";
#else
		Shell = "/usr/bin/sh";
#endif
	if(pipe(p) < 0)
		return(NULL);
	myside = tst(p[WTR], p[RDR]);
	yourside = tst(p[RDR], p[WTR]);
	if((pid = fork()) == 0) {
		/* myside and yourside reverse roles in child */
		int	stdio;

		stdio = tst(0, 1);
		(void) close(myside);
		(void) close(stdio);
		(void) fcntl(yourside, 0, stdio);
		(void) close(yourside);
		(void) execlp(Shell, Shell, "-c", cmd, (char *)0);
		perror(Shell);
		_exit(1);
	}
	if(pid == (pid_t)-1)
		return(NULL);
	popen_pid[myside] = pid;
	(void) close(yourside);
	return(fdopen(myside, mode));
}

int
npclose(FILE *ptr)
{
	register int f;
	register pid_t r;
	int status;
	void (*istat)(int), (*qstat)(int);

	f = fileno(ptr);
	(void) fclose(ptr);
	istat = sigset(SIGINT, SIG_IGN);
	qstat = sigset(SIGQUIT, SIG_IGN);
	while((r = wait(&status)) != popen_pid[f] && r != (pid_t)-1)
		;
	if(r == (pid_t)-1)
		status = -1;
	(void) sigset(SIGINT, istat);
	(void) sigset(SIGQUIT, qstat);
	return(status);
}
