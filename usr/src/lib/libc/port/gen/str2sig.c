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
 * Copyright (c) 2014, Joyent, Inc.  All rights reserved.
 */

/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved  	*/

#include "lint.h"
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <sys/types.h>
#include <errno.h>

typedef struct signame {
	const char *sigstr;
	const int   signum;
} signame_t;

static signame_t signames[] = {
	{ "EXIT",	0 },
	{ "HUP",	SIGHUP },
	{ "INT",	SIGINT },
	{ "QUIT",	SIGQUIT },
	{ "ILL",	SIGILL },
	{ "TRAP",	SIGTRAP },
	{ "ABRT",	SIGABRT },
	{ "IOT",	SIGIOT },
	{ "EMT",	SIGEMT },
	{ "FPE",	SIGFPE },
	{ "KILL",	SIGKILL },
	{ "BUS",	SIGBUS },
	{ "SEGV",	SIGSEGV },
	{ "SYS",	SIGSYS },
	{ "PIPE",	SIGPIPE },
	{ "ALRM",	SIGALRM },
	{ "TERM",	SIGTERM },
	{ "USR1",	SIGUSR1 },
	{ "USR2",	SIGUSR2 },
	{ "CLD",	SIGCLD },
	{ "CHLD",	SIGCHLD },
	{ "PWR",	SIGPWR },
	{ "WINCH",	SIGWINCH },
	{ "URG",	SIGURG },
	{ "POLL",	SIGPOLL },
	{ "IO",		SIGPOLL },
	{ "STOP",	SIGSTOP },
	{ "TSTP",	SIGTSTP },
	{ "CONT",	SIGCONT },
	{ "TTIN",	SIGTTIN },
	{ "TTOU",	SIGTTOU },
	{ "VTALRM",	SIGVTALRM },
	{ "PROF",	SIGPROF },
	{ "XCPU",	SIGXCPU },
	{ "XFSZ",	SIGXFSZ },
	{ "WAITING",	SIGWAITING },
	{ "LWP",	SIGLWP },
	{ "FREEZE",	SIGFREEZE },
	{ "THAW",	SIGTHAW },
	{ "CANCEL",	SIGCANCEL },
	{ "LOST",	SIGLOST },
	{ "XRES", 	SIGXRES },
	{ "JVM1",	SIGJVM1 },
	{ "JVM2",	SIGJVM2 },
	{ "INFO",	SIGINFO },
	{ "RTMIN",	_SIGRTMIN },
	{ "RTMIN+1",	_SIGRTMIN+1 },
	{ "RTMIN+2",	_SIGRTMIN+2 },
	{ "RTMIN+3",	_SIGRTMIN+3 },
	{ "RTMIN+4",	_SIGRTMIN+4 },
	{ "RTMIN+5",	_SIGRTMIN+5 },
	{ "RTMIN+6",	_SIGRTMIN+6 },
	{ "RTMIN+7",	_SIGRTMIN+7 },
	{ "RTMIN+8",	_SIGRTMIN+8 },
	{ "RTMIN+9",	_SIGRTMIN+9 },
	{ "RTMIN+10",	_SIGRTMIN+10 },
	{ "RTMIN+11",	_SIGRTMIN+11 },
	{ "RTMIN+12",	_SIGRTMIN+12 },
	{ "RTMIN+13",	_SIGRTMIN+13 },
	{ "RTMIN+14",	_SIGRTMIN+14 },
	{ "RTMIN+15",	_SIGRTMIN+15 },
	{ "RTMAX-15",	_SIGRTMAX-15 },
	{ "RTMAX-14",	_SIGRTMAX-14 },
	{ "RTMAX-13",	_SIGRTMAX-13 },
	{ "RTMAX-12",	_SIGRTMAX-12 },
	{ "RTMAX-11",	_SIGRTMAX-11 },
	{ "RTMAX-10",	_SIGRTMAX-10 },
	{ "RTMAX-9",	_SIGRTMAX-9 },
	{ "RTMAX-8",	_SIGRTMAX-8 },
	{ "RTMAX-7",	_SIGRTMAX-7 },
	{ "RTMAX-6",	_SIGRTMAX-6 },
	{ "RTMAX-5",	_SIGRTMAX-5 },
	{ "RTMAX-4",	_SIGRTMAX-4 },
	{ "RTMAX-3",	_SIGRTMAX-3 },
	{ "RTMAX-2",	_SIGRTMAX-2 },
	{ "RTMAX-1",	_SIGRTMAX-1 },
	{ "RTMAX",	_SIGRTMAX },
};

#define	SIGCNT	(sizeof (signames) / sizeof (struct signame))

static int	str2long(const char *, long *);

static int
str2long(const char *p, long *val)
{
	char *q;
	int error;
	int saved_errno = errno;

	errno = 0;
	*val = strtol(p, &q, 10);

	error = ((errno != 0 || q == p || *q != '\0') ? -1 : 0);
	errno = saved_errno;

	return (error);
}

int
str2sig(const char *s, int *sigp)
{
	const struct signame *sp;

	if (*s >= '0' && *s <= '9') {
		long val;

		if (str2long(s, &val) == -1)
			return (-1);

		for (sp = signames; sp < &signames[SIGCNT]; sp++) {
			if (sp->signum == val) {
				*sigp = sp->signum;
				return (0);
			}
		}
		return (-1);
	} else {
		for (sp = signames; sp < &signames[SIGCNT]; sp++) {
			if (strcmp(sp->sigstr, s) == 0) {
				*sigp = sp->signum;
				return (0);
			}
		}
		return (-1);
	}
}

int
sig2str(int i, char *s)
{
	const struct signame *sp;

	for (sp = signames; sp < &signames[SIGCNT]; sp++) {
		if (sp->signum == i) {
			(void) strcpy(s, sp->sigstr);
			return (0);
		}
	}
	return (-1);
}
