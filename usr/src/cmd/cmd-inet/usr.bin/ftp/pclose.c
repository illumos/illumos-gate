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
 *	Copyright 1996 Sun Microsystems, Inc.  All rights reserved.
 *	Use is subject to license terms.
 */

/*	Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T	*/
/*	All Rights Reserved  	*/

/*
 *	University Copyright- Copyright (c) 1982, 1986, 1988
 *	The Regents of the University of California
 *	All Rights Reserved
 *
 *	University Acknowledgment- Portions of this document are derived from
 *	software developed by the University of California, Berkeley, and its
 *	contributors.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "ftp_var.h"

#ifndef sigmask
#define	sigmask(m)	(1 << ((m)-1))
#endif

#define	set2mask(setp) ((setp)->__sigbits[0])
#define	mask2set(mask, setp) \
	((mask) == -1 ? sigfillset(setp) : (((setp)->__sigbits[0]) = (mask)))


static int
sigsetmask(int mask)
{
	sigset_t oset;
	sigset_t nset;

	(void) sigprocmask(0, (sigset_t *)0, &nset);
	mask2set(mask, &nset);
	(void) sigprocmask(SIG_SETMASK, &nset, &oset);
	return (set2mask(&oset));
}

static int
sigblock(int mask)
{
	sigset_t oset;
	sigset_t nset;

	(void) sigprocmask(0, (sigset_t *)0, &nset);
	mask2set(mask, &nset);
	(void) sigprocmask(SIG_BLOCK, &nset, &oset);
	return (set2mask(&oset));
}

#define	signal(s, f)	sigset(s, f)

#define	tst(a, b)	(*mode == 'r'? (b) : (a))
#define	RDR		0
#define	WTR		1
#define	NOFILES		20	/* just in case */

static	pid_t *popen_pid;
static	rlim_t nfiles = 0;

FILE *
mypopen(char *cmd, char *mode)
{
	int p[2];
	pid_t pid;
	int myside, remside, i;
	struct rlimit rl;

	if (nfiles <= 0) {
		if (getrlimit(RLIMIT_NOFILE, &rl) == 0)
			nfiles = rl.rlim_max;
		else
			nfiles = NOFILES;
	}
	if (popen_pid == NULL) {
		popen_pid = (pid_t *)malloc((unsigned)nfiles *
		    sizeof (*popen_pid));
		if (popen_pid == NULL)
			return (NULL);
		for (i = 0; i < nfiles; i++)
			popen_pid[i] = (pid_t)-1;
	}
	if (pipe(p) < 0)
		return (NULL);
	myside = tst(p[WTR], p[RDR]);
	remside = tst(p[RDR], p[WTR]);
	if ((pid = vfork()) == 0) {
		/* myside and remside reverse roles in child */
		(void) close(myside);
		if (remside != tst(0, 1)) {
			(void) dup2(remside, tst(0, 1));
			(void) close(remside);
		}
		execl("/bin/sh", "sh", "-c", cmd, (char *)NULL);
		_exit(127);
	}
	if (pid == (pid_t)-1) {
		(void) close(myside);
		(void) close(remside);
		return (NULL);
	}
	popen_pid[myside] = pid;
	(void) close(remside);
	return (fdopen(myside, mode));
}

/*ARGSUSED*/
static void
pabort(int sig)
{
	extern int mflag;

	mflag = 0;
}

int
mypclose(FILE *ptr)
{
	pid_t child, pid;
	int omask;
	void (*istat)();
	int status;

	child = popen_pid[fileno(ptr)];
	popen_pid[fileno(ptr)] = (pid_t)-1;
	(void) fclose(ptr);
	if (child == (pid_t)-1)
		return (-1);
	istat = signal(SIGINT, pabort);
	omask = sigblock(sigmask(SIGQUIT)|sigmask(SIGHUP));
	while ((pid = wait(&status)) != child && pid != (pid_t)-1)
		;
	(void) sigsetmask(omask);
	(void) signal(SIGINT, istat);
	return (pid == (pid_t)-1 ? -1 : 0);
}
