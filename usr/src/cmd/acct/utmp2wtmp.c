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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 *	create entries for users who are still logged on when accounting
 *	is being run. Look at utmpx, and update the time stamp. New info
 *	goes to wtmpx. Called by runacct.
 */

#include <stdio.h>
#include <sys/types.h>
#include <utmpx.h>
#include <time.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>

int
main(int argc, char **argv)
{
	struct utmpx *utmpx;
	FILE *fp;

	fp = fopen(WTMPX_FILE, "a+");
	if (fp == NULL) {
		fprintf(stderr, "%s: %s: %s\n", argv[0],
		    WTMPX_FILE, strerror(errno));
		exit(1);
	}

	while ((utmpx = getutxent()) != NULL) {
		if ((utmpx->ut_type == USER_PROCESS) && !(nonuserx(*utmpx))) {
			time(&utmpx->ut_xtime);
			fwrite(utmpx, sizeof (*utmpx), 1, fp);
		}
	}
	fclose(fp);
	exit(0);
}
