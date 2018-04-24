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
 * Copyright (c) 1998 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#include <sys/types.h>
#include <signal.h>
#include <errno.h>
#include <utmpx.h>
#include <stdio.h>
#include <unistd.h>

int
main(int argc, char *argv[])
{
	int sig;
	struct utmpx *u;
	char usage[] = "usage: killall [signal]\n";
	char perm[] = "permission denied\n";

	if (geteuid() != 0) {
		(void) write(2, perm, sizeof (perm)-1);
		return (1);
	}
	switch (argc) {
		case 1:
			sig = SIGTERM;
			break;
		case 2:
			if (str2sig(argv[1], &sig) == 0)
				break;
			/* FALLTHROUGH */
		default:
			(void) write(2, usage, sizeof (usage)-1);
			return (1);
	}

	while ((u = getutxent()) != NULL) {
		if ((u->ut_type == LOGIN_PROCESS) ||
		    (u->ut_type == USER_PROCESS))
			(void) kill(u->ut_pid, sig);
	}
	endutxent();

	return (0);
}
