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

/* 
 * This short program is called by a co-process if it wishes to 
 * communicate asynchronously with the controlling FMLI process during
 * the course of its execution.  It blocks til FMLI is ready for a
 * signal then sends a SIGUSR2. 
 */

#include <stdio.h>
#include <signal.h>
#include <fcntl.h>
#include "sizes.h"


char Semaphore[PATHSIZ] = "/tmp/FMLIsem.";

int
main(int argc, char *argv[])
{
	char *vpid;
	char *getenv();

	if ((vpid = getenv("VPID")) == NULL)
		exit(1);
	strcat(Semaphore, vpid);
	fflush(stdout);
	fflush(stderr);
	/*
	 * The reason for the close(open) is to
	 * block until FACE says its is OK
	 * to send a signal ... A signal when
	 * FACE is updating the screen
	 * can create garbage .....
	 */
	close(open(Semaphore, O_WRONLY));
	kill(strtol(vpid, (char **)NULL, 0), SIGUSR2); /* EFT abs k16 */
	return (0);
}
