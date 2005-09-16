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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1985, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <signal.h>
#include <sys/types.h>	/* EFT abs k16 */
#include "wish.h"

static void sig_nothing(int sig);

int
suspend(cmd)
char *cmd;
{
    char suspath[40];
    pid_t vpid;			/* EFT abs k16 */
    FILE *fp;
	
    sigset(SIGUSR1, sig_nothing);

    if ((vpid = strtol(getenv("VPID"), (char **)NULL, 0)) == 0) /* EFT k16 */
    {
#ifdef _DEBUG
	_debug(stderr, "Unable to get VPID\n");
#endif
	return(FAIL);
    }

    sprintf(suspath, "/tmp/suspend%d", vpid);
    if ((fp = fopen(suspath, "w")) == NULL) {
#ifdef _DEBUG
	_debug(stderr, "Unable to open suspend file %s\n", suspath);
#endif
	return(FAIL);
    }
    (void) fprintf(fp, "%d\n%s\n", getpid(), cmd ? cmd : "");
    (void) fclose(fp);

    if (kill(vpid, SIGUSR1) == FAIL) {
#ifdef _DEBUG
	_debug(stderr, "Unable to send sigusr1 to face pid=%d\n", vpid);
#endif
	return(FAIL);
    }
    pause();
    return(SUCCESS);
}


static void
sig_nothing(int sig)
{
	/* do nothing, just catch the signal and return */
	return;
}
