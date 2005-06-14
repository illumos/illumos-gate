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
 * Copyright 1992 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1985, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <signal.h>
#include <sys/types.h>    /* EFT abs k16 */
#include <errno.h>
#include "wish.h"
#include "token.h"
#include "slk.h"
#include "actrec.h"
#include "proc.h"
#include "procdefs.h"
#include "terror.h"
#include "sizes.h"

extern struct proc_rec PR_all[];
extern bool Suspend_interupt;
extern char *Suspend_window;

/* extern int errno;    EFT abs k16 */

int
proc_current(rec)
struct actrec *rec;
{
    int p = rec->id;
    pid_t pid, w;	 /* EFT abs k16 */
    int status;
    extern int _Debug;
    void sigcatch();
    void (*oldquit) (), (*oldint) ();
    int set_ret_val();

    if (PR_all[p].status == ST_DEAD)
	return(FAIL);

    /* if process is not already forked, fork it else resume it */

    vt_before_fork();
    fork_clrscr();
    if (PR_all[p].pid == NOPID) {
#ifdef _DEBUG
	_debug(stderr, "NEW PROCESS FORKING\n");
#endif
	switch (pid = fork()) {
	case FAIL:
#ifdef _DEBUG
	    _debug(stderr, "Fork failed with errno=%d\n", errno);
#endif
	    error(MISSING, "process fork failed");
	    return(FAIL);
	case 0:			/* child */
#ifdef _DEBUG
	    if (_Debug)
		(void) freopen("/dev/tty", "w+", stderr);
#endif
	    sigset(SIGINT, SIG_DFL);
	    sigset(SIGQUIT, SIG_DFL);
	    execvp(PR_all[p].name, PR_all[p].argv);
	    error_exec(errno);
	    child_error(NOEXEC, PR_all[p].name); /* abs k15 */
	    _exit(255);
	default:
	    oldquit = sigset(SIGQUIT, SIG_IGN); /* changed from..  */
	    oldint  = sigset(SIGINT, SIG_IGN); /* ..signal()  abs */
	    PR_all[p].pid = PR_all[p].respid = pid;
	    break;
	}
    } else {			/* resume */
	pid = PR_all[p].pid;
#ifdef _DEBUG
	_debug(stderr, "resuming pid %d by signaling %d\n", pid, PR_all[p].respid);
#endif
	if (PR_all[p].flags & PR_CLOSING) {
	    fflush(stdout);
	    fflush(stderr);
	    printf("You are returning to a suspended activity.  This activity\r\n");
	    printf("must be ended before you can complete logging out.\r\n");
	    printf("Please take whatever steps are necessary to end this\r\n");
	    printf("activity.\r\n\n");
	    fflush(stdout);
	    sleep(3);
	} else {
	    fflush(stdout);
	    fflush(stderr);
	    printf("You are returning to a suspended activity. \r\n");
	    fflush(stdout);
	    sleep(3);
	}

	if (kill(PR_all[p].respid, SIGUSR1) == FAIL) {
#ifdef _DEBUG
	    _debug(stderr, "RESUME SIGNAL FAILED WITH ERRNO=%d\n", errno);
#endif
	    return(FAIL);
	}
    }
    PR_all[p].status = ST_RUNNING;

#ifdef _DEBUG
    _debug(stderr, "Waiting for pid %d\n", pid);
#endif
    status = 0;
    Suspend_interupt = FALSE;

    while ((w = wait(&status)) != pid) {
	if ((w == FAIL && errno != EINTR) || Suspend_interupt) {
#ifdef _DEBUG
	    _debug(stderr, "Woken while waiting for %d\n", pid);
#endif
	    break;
	}
    }
    if (Suspend_interupt) {
#ifdef _DEBUG
	_debug(stderr, "Process %d suspended, making non-current\n", pid);
#endif
	if (Suspend_window == NULL)
	    ar_backup();	/* go back to previous activation record */
	else {
	    objop("OPEN", NULL, Suspend_window, NULL);
	    free(Suspend_window);
	    Suspend_window = NULL;
	}
    } else {
	(void) set_ret_val(status);
#ifdef _DEBUG
	_debug(stderr, "Process terminated, closing actrec\n");
#endif
	PR_all[p].pid = PR_all[p].respid = NOPID;
	if ((PR_all[p].flags == PR_ERRPROMPT && status>>8 != 0) ||
	    (PR_all[p].flags & ~PR_CLOSING) == 0) {
	    char buf[PATHSIZ];

	    printf("\r\nPress ENTER to continue");
	    fflush(stdout);
	    fgets(buf, PATHSIZ, stdin);
	}
	if ((PR_all[p].flags & PR_CLOSING) == 0)
	    ar_close(rec, FALSE);
    }
    /*	signal(SIGINT, oldint);
	signal(SIGQUIT, oldquit);
	abs */
    sigset(SIGINT, oldint);
    sigset(SIGQUIT, oldquit);
    vt_after_fork();
    return(SUCCESS);
}

void sigcatch(sig)
int sig;
{
/*	signal(sig, SIG_IGN);
	signal(sig, sigcatch);
abs */
        sigignore(sig);
	sigset(sig, sigcatch);
}
