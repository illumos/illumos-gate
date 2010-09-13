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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>
#include <string.h>
#include <signal.h>
#include <stropts.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/termio.h>
#include <libproc.h>
#include "ramdata.h"
#include "proto.h"

/*
 * Routines related to interprocess communication
 * among the truss processes which are controlling
 * multiple traced processes.
 */

/*
 * Function prototypes for static routines in this module.
 */
void	Ecritical(int);
void	Xcritical(int);

/*
 * Ensure everyone keeps out of each other's way
 * while writing lines of trace output.
 */
void
Flush()
{
	/*
	 * Except for regions bounded by Eserialize()/Xserialize(),
	 * this is the only place anywhere in the program where a
	 * write() to the trace output file takes place, so here
	 * is where we detect errors writing to the output.
	 */

	errno = 0;

	Ecritical(0);
	(void) fflush(stdout);
	Xcritical(0);

	if (ferror(stdout) && errno)	/* error on write(), probably EPIPE */
		interrupt = SIGTERM;		/* post an interrupt */
}

/*
 * Eserialize() and Xserialize() are used to bracket
 * a region which may produce large amounts of output,
 * such as showargs()/dumpargs().
 */

void
Eserialize()
{
	/* serialize output */
	Ecritical(0);
}

void
Xserialize()
{
	(void) fflush(stdout);
	Xcritical(0);
}

/*
 * Enter critical region --- Wait on mutex, lock out other processes.
 * Lock zero is used to serialize output in situations where multiple processes
 * may be writing to stdout/stderr and order must be preserved.  Most of these
 * are in expound.c
 * Lock one is used to protect the table of processes currently being traced
 * every time a pid is added or removed from the table Ecritical(1)/Xcritical(1)
 * get called.
 */
void
Ecritical(int num)
{
	int rv;

	if (num == 0)
		rv = mutex_lock(&gps->ps_mutex0);
	else if (num == 1)
		rv = mutex_lock(&gps->ps_mutex1);
	else
		abend("Invalid mutex specified", NULL);

	if (rv != 0) {
		char mnum[2];
		mnum[0] = '0' + num;
		mnum[1] = '\0';
		errno = rv;
		perror(command);
		errmsg("cannot grab mutex #", mnum);
	}
}

/*
 * Exit critical region ---
 * Release other processes waiting on mutex.
 */
void
Xcritical(int num)
{
	int rv;

	if (num == 0)
		rv = mutex_unlock(&gps->ps_mutex0);
	else if (num == 1)
		rv = mutex_unlock(&gps->ps_mutex1);
	else
		abend("Invalid mutex specified", NULL);


	if (rv != 0) {
		char mnum[2];
		mnum[0] = '0' + num;
		mnum[1] = '\0';
		errno = rv;
		perror(command);
		errmsg("cannot release mutex #", mnum);
	}
}

/*
 * Add process to set of those being traced.
 */
void
procadd(pid_t spid, const char *lwplist)
{
	int i;
	int j = -1;

	if (gps == NULL)
		return;

	Ecritical(1);
	for (i = 0; i < sizeof (gps->tpid) / sizeof (gps->tpid[0]); i++) {
		if (gps->tpid[i] == 0) {
			if (j == -1)	/* remember first vacant slot */
				j = i;
			if (gps->spid[i] == 0)	/* this slot is better */
				break;
		}
	}
	if (i < sizeof (gps->tpid) / sizeof (gps->tpid[0]))
		j = i;
	if (j >= 0) {
		gps->tpid[j] = getpid();
		gps->spid[j] = spid;
		gps->lwps[j] = lwplist;
	}
	Xcritical(1);
}

/*
 * Delete process from set of those being traced.
 */
void
procdel()
{
	int i;
	pid_t tpid;

	if (gps == NULL)
		return;

	tpid = getpid();

	Ecritical(1);
	for (i = 0; i < sizeof (gps->tpid) / sizeof (gps->tpid[0]); i++) {
		if (gps->tpid[i] == tpid) {
			gps->tpid[i] = 0;
			break;
		}
	}
	Xcritical(1);
}

/*
 * Determine if the lwp for this process should be traced.
 */
int
lwptrace(pid_t spid, lwpid_t lwpid)
{
	int i;
	pid_t tpid;
	const char *lwps;

	if (gps == NULL)
		return (0);

	tpid = getpid();

	Ecritical(1);
	for (i = 0; i < sizeof (gps->tpid) / sizeof (gps->tpid[0]); i++) {
		if (gps->tpid[i] == tpid &&
		    gps->spid[i] == spid)
			break;
	}
	lwps = gps->lwps[i];
	Xcritical(1);

	return (proc_lwp_in_set(lwps, lwpid));
}

/*
 * Check for open of a /proc/nnnnn file.
 * Return 0 if this is not an open of a /proc file.
 * Return 1 if the process opened itself.
 * Return 2 if the process failed to open another process
 * in truss's set of controlled processes.
 * Return 3 if the process successfully opened another process
 * in truss's set of controlled processes.
 * We notify and wait for the other controlling truss process
 * to terminate before returning in cases 2 and 3.
 */
/* ARGSUSED */
int
checkproc(private_t *pri)
{
	char *path = pri->sys_path;
	const pstatus_t *Psp = Pstatus(Proc);
	struct ps_lwphandle *Lwp = pri->Lwp;
	const lwpstatus_t *Lsp = pri->lwpstat;
	int what = Lsp->pr_what;	/* one of the SYS_open* syscalls */
	int err = Lsp->pr_errno;
	int pid;
	int i;
	const char *dirname;
	char *next;
	char *sp1;
	char *sp2;
	prgreg_t pc;

	/*
	 * A bit heuristic ...
	 * Test for the cases:
	 *	1234
	 *	1234/as
	 *	1234/ctl
	 *	1234/lwp/24/lwpctl
	 *	.../1234
	 *	.../1234/as
	 *	.../1234/ctl
	 *	.../1234/lwp/24/lwpctl
	 * Insert a '\0', if necessary, so the path becomes ".../1234".
	 *
	 * Along the way, watch out for /proc/self and /proc/1234/lwp/agent
	 */
	if ((sp1 = strrchr(path, '/')) == NULL)		/* last component */
		/* EMPTY */;
	else if (isdigit(*(sp1+1))) {
		sp1 += strlen(sp1);
		while (--sp1 > path && isdigit(*sp1))
			;
		if (*sp1 != '/')
			return (0);
	} else if (strcmp(sp1+1, "as") == 0 ||
	    strcmp(sp1+1, "ctl") == 0) {
		*sp1 = '\0';
	} else if (strcmp(sp1+1, "lwpctl") == 0) {
		/*
		 * .../1234/lwp/24/lwpctl
		 * ............   ^-- sp1
		 */
		if (sp1-6 >= path && strncmp(sp1-6, "/agent", 6) == 0)
			sp1 -= 6;
		else {
			while (--sp1 > path && isdigit(*sp1))
				;
		}
		if (*sp1 != '/' ||
		    (sp1 -= 4) <= path ||
		    strncmp(sp1, "/lwp", 4) != 0)
			return (0);
		*sp1 = '\0';
	} else if (strcmp(sp1+1, "self") != 0) {
		return (0);
	}

	if ((sp2 = strrchr(path, '/')) == NULL)
		dirname = path;
	else
		dirname = sp2 + 1;

	if (strcmp(dirname, "self") == 0) {
		pid = Psp->pr_pid;
	} else if ((pid = strtol(dirname, &next, 10)) < 0 ||
	    *next != '\0') {	/* dirname not a number */
		if (sp1 != NULL)
			*sp1 = '/';
		return (0);
	}
	if (sp2 == NULL)
		dirname = ".";
	else {
		*sp2 = '\0';
		dirname = path;
	}

	if (!Pisprocdir(Proc, dirname) || /* file not in a /proc directory */
	    pid == getpid() ||		/* process opened truss's /proc file */
	    pid == 0) {			/* process opened process 0 */
		if (sp1 != NULL)
			*sp1 = '/';
		if (sp2 != NULL)
			*sp2 = '/';
		return (0);
	}
	if (sp1 != NULL)
		*sp1 = '/';
	if (sp2 != NULL)
		*sp2 = '/';

	/*
	 * Process did open a /proc file ---
	 */
	if (pid == Psp->pr_pid) {	/* process opened its own /proc file */
		/*
		 * In SunOS 5.6 and beyond, self-opens always succeed.
		 */
		return (1);
	}

	/*
	 * Search for a matching pid in our set of controlled processes.
	 */
	for (i = 0; i < sizeof (gps->tpid)/sizeof (gps->tpid[0]); i++) {
		if (gps->spid[i] == pid) {
			pid = gps->tpid[i];
			break;
		}
	}
	if (i >= sizeof (gps->tpid) / sizeof (gps->tpid[0])) {
		/*
		 * The process opened a /proc file, but not one we care about.
		 */
		return (0);
	}

	/*
	 * Notify and wait for the controlling process to terminate.
	 */
	while (pid && gps->tpid[i] == pid) {
		if (kill(pid, SIGUSR1) == -1)
			break;
		(void) usleep(1000000);
	}
	Ecritical(1);
	if (gps->tpid[i] == 0)
		gps->spid[i] = 0;
	Xcritical(1);

	if (err) {	/* prepare to reissue the failed open() system call */
#if defined(__sparc)
		(void) Lgetareg(Lwp, R_PC, &pc);
		if (pri->sys_indirect) {
			(void) Lputareg(Lwp, R_G1, (prgreg_t)SYS_syscall);
			(void) Lputareg(Lwp, R_O0, (prgreg_t)what);
			for (i = 0; i < 5; i++)
				(void) Lputareg(Lwp, R_O1+i, pri->sys_args[i]);
		} else {
			(void) Lputareg(Lwp, R_G1, (prgreg_t)what);
			for (i = 0; i < 6; i++)
				(void) Lputareg(Lwp, R_O0+i, pri->sys_args[i]);
		}
		(void) Lputareg(Lwp, R_nPC, pc);
#elif defined(__amd64)
		(void) Lgetareg(Lwp, R_PC, &pc);
		(void) Lputareg(Lwp, REG_RAX, (prgreg_t)what);
#elif defined(__i386)
		(void) Lgetareg(Lwp, R_PC, &pc);
		(void) Lputareg(Lwp, EAX, (prgreg_t)what);
#else
#error "unrecognized architecture"
#endif
		(void) Pissyscall_prev(Proc, pc, (uintptr_t *)&pc);
		(void) Lputareg(Lwp, R_PC, pc);
		return (2);
	}

	return (3);
}
