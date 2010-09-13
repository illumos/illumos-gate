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

/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved  	*/

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Return the number of the slot in the utmp file
 * corresponding to the current user: try for file 0, 1, 2.
 * Returns -1 if slot not found.
 */

#include "lint.h"
#include <string.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <utmpx.h>
#include <stdlib.h>
#include <pthread.h>

#ifndef TRUE
#define	TRUE 1
#define	FALSE 0
#endif

int
ttyslot(void)
{
	struct futmpx ubuf;
	char *p;
	int s;
	int ret = -1;
	int console = FALSE;
	char ttynm[128];
	FILE *fp;
	int cancel_state;

	/*
	 * The UNIX98 Posix conformance test suite requires
	 * ttyslot() to not be a cancellation point.
	 */
	(void) pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &cancel_state);

	if ((p = ttyname_r(0, ttynm, 128)) != NULL ||
	    (p = ttyname_r(1, ttynm, 128)) != NULL ||
	    (p = ttyname_r(2, ttynm, 128)) != NULL) {
		if (strncmp(p, "/dev/", 5) == 0)
			p += 5;
		if (strcmp(p, "console") == 0)
			console = TRUE;
		s = 0;
		if ((fp = fopen(UTMPX_FILE, "rF")) != NULL) {
			while ((fread(&ubuf, sizeof (ubuf), 1, fp)) == 1) {
				if ((ubuf.ut_type == INIT_PROCESS ||
				    ubuf.ut_type == LOGIN_PROCESS ||
				    ubuf.ut_type == USER_PROCESS) &&
				    strncmp(p, ubuf.ut_line,
				    sizeof (ubuf.ut_line)) == 0) {
					ret = s;
					if (!console ||
					    strncmp(ubuf.ut_host, ":0", 2) == 0)
						break;
				}
				s++;
			}
			(void) fclose(fp);
		}
	}

	(void) pthread_setcancelstate(cancel_state, NULL);
	return (ret);
}
