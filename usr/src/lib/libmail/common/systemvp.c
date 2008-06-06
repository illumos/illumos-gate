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

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 *  These routines are based on the standard UNIX stdio popen/pclose
 *  routines. This version takes an argv[][] argument instead of a string
 *  to be passed to the shell. The routine execvp() is used to call the
 *  program, hence the name popenvp() and the argument types.
 *
 *  This routine avoids an extra shell completely, along with not having
 *  to worry about quoting conventions in strings that have spaces,
 *  quotes, etc.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include "libmail.h"
#include <signal.h>
#include <unistd.h>
#include <wait.h>

pid_t
systemvp(char *file, char **argv, int resetid)
{
	int	status;
	pid_t	pid, w;
	void (*istat)(int), (*qstat)(int);

	if ((pid = fork()) == 0) {
		if (resetid) {
			(void) setgid(getgid());
			(void) setuid(getuid());
		}
		(void) execvp(file, argv);
		_exit(127);
	}
	istat = signal(SIGINT, SIG_IGN);
	qstat = signal(SIGQUIT, SIG_IGN);
	do {
		w = wait(&status);
	} while (w != pid && w != (pid_t)-1);
	(void) signal(SIGINT, istat);
	(void) signal(SIGQUIT, qstat);
	return ((w == (pid_t)-1)? w: (pid_t)status);
}
