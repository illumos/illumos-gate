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

#pragma weak _cuserid = cuserid

#include "lint.h"
#include <stdio.h>
#include <pwd.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>

static char res[L_cuserid];

char *
cuserid(char *s)
{
	struct passwd *pw;
	struct passwd pwd;
	char buffer[BUFSIZ];
	char utname[L_cuserid];
	char *p;
	int cancel_state;

	/*
	 * The UNIX98 Posix conformance test suite requires
	 * cuserid() to not be a cancellation point.
	 */
	(void) pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &cancel_state);

	if (s == NULL)
		s = res;
	if ((p = getlogin_r(utname, L_cuserid)) != NULL) {
		(void) strlcpy(s, p, L_cuserid);
	} else if ((pw = getpwuid_r(getuid(), &pwd, buffer, BUFSIZ)) != NULL) {
		(void) strlcpy(s, pw->pw_name, L_cuserid);
	} else {
		*s = '\0';
		s = NULL;
	}

	(void) pthread_setcancelstate(cancel_state, NULL);
	return (s);
}
