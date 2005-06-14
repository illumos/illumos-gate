/*
 * Copyright (c) 1995, by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"
	  /* from UCB 5.2 85/06/05 */

/*
 * Copyright (c) 1980 Regents of the University of California.
 * All rights reserved.  The Berkeley software License Agreement
 * specifies the terms and conditions for redistribution.
 */

#include <stdio.h>
#include <signal.h>
#include <vfork.h>

#define	tst(a,b)	(*mode == 'r'? (b) : (a))
#define	RDR	0
#define	WTR	1

extern	char *malloc();
extern	int execl(), vfork(), pipe(), close(), fcntl();

static	int *popen_pid;
static	int nfiles;

FILE *
popen(cmd,mode)
	char *cmd;
	char *mode;
{
	int p[2];
	register int *poptr;
	register int myside, hisside, pid;

	if (nfiles <= 0)
		nfiles = getdtablesize();
	if (popen_pid == NULL) {
		popen_pid = (int *)malloc(nfiles * sizeof *popen_pid);
		if (popen_pid == NULL)
			return (NULL);
		for (pid = 0; pid < nfiles; pid++)
			popen_pid[pid] = -1;
	}
	if (pipe(p) < 0)
		return (NULL);
	myside = tst(p[WTR], p[RDR]);
	hisside = tst(p[RDR], p[WTR]);
	if ((pid = vfork()) == 0) {
		/* myside and hisside reverse roles in child */
		int	stdio;

		/* close all pipes from other popen's */
		for (poptr = popen_pid; poptr < popen_pid+nfiles; poptr++) {
			if(*poptr >= 0)
				close(poptr - popen_pid);
		}
		stdio = tst(0, 1);
		(void) close(myside);
		if (hisside != stdio) {
			(void) dup2(hisside, stdio);
			(void) close(hisside);
		}
		(void) execl("/bin/sh", "sh", "-c", cmd, (char *)NULL);
		_exit(127);
	}
	if (pid == -1) {
		close(myside);
		close(hisside);
		return (NULL);
	}
	popen_pid[myside] = pid;
	close(hisside);
	return (fdopen(myside, mode));
}

int
pclose(ptr)
	FILE *ptr;
{
	int child = -1;
	int pid, status, omask;

	if (popen_pid != NULL) {
		child = popen_pid[fileno(ptr)];
		popen_pid[fileno(ptr)] = -1;
	}
	fclose(ptr);
	if (child == -1)
		return (-1);
	omask = sigblock(sigmask(SIGINT)|sigmask(SIGQUIT)|sigmask(SIGHUP));
	while ((pid = waitpid(child, &status, 0)) != child && pid != -1)
		;
	(void) sigsetmask(omask);
	return (pid == -1 ? -1 : status);
}
