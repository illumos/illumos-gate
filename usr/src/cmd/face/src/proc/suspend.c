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


#ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.4	*/
/*LINTLIBRARY*/

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <sys/types.h>
#include "wish.h"

int
suspend(cmd)
char *cmd;
{
	char suspath[40];
	pid_t vpid;
	FILE *fp;
	static void sig_nothing();
	
	signal(SIGUSR1, sig_nothing);

	if ((vpid = (pid_t) atol(getenv("VPID"))) == 0) {
#ifdef _DEBUG
		_debug(stderr, "Unable to get VPID\n");
#endif
		return(FAIL);
	}

	sprintf(suspath, "/tmp/suspend%ld", vpid);
	if ((fp = fopen(suspath, "w")) == NULL) {
#ifdef _DEBUG
		_debug(stderr, "Unable to open suspend file %s\n", suspath);
#endif
		return(FAIL);
	}
	(void) fprintf(fp, "%ld\n%s\n", getpid(), cmd ? cmd : "");
	(void) fclose(fp);

	if (kill(vpid, SIGUSR1) == FAIL) {
#ifdef _DEBUG
		_debug(stderr, "Unable to send sigusr1 to face pid=%ld\n", vpid);
#endif
		return(FAIL);
	}
	pause();
	return(SUCCESS);
}

/*ARGSUSED*/
static void
sig_nothing(sig)
int sig;
{
	/* do nothing, just catch the signal and return */
	return;
}
