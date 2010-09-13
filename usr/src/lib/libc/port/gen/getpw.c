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

#include "lint.h"
#include "file64.h"
#include <sys/types.h>
#include <mtlib.h>
#include <ctype.h>
#include <thread.h>
#include <synch.h>
#include <stdio.h>
#include "stdiom.h"
#include "libc.h"

static FILE *pwf;
static mutex_t _pwlock = DEFAULTMUTEX;
const char *PASSWD = "/etc/passwd";

int
getpw(uid_t uid, char buf[])
{
	int n, c;
	char *bp;
	FILE *fp;
	rmutex_t *lk;

	if (pwf == NULL) {
		fp = fopen(PASSWD, "rF");
		lmutex_lock(&_pwlock);
		if (pwf == NULL) {
			if ((pwf = fp) == NULL) {
				lmutex_unlock(&_pwlock);
				return (1);
			}
			fp = NULL;
		}
		lmutex_unlock(&_pwlock);
		if (fp != NULL)		/* someone beat us to it */
			(void) fclose(fp);
	}

	FLOCKFILE(lk, pwf);
	_rewind_unlocked(pwf);

	for (;;) {
		bp = buf;
		while ((c = GETC(pwf)) != '\n') {
			if (c == EOF) {
				FUNLOCKFILE(lk);
				return (1);
			}
			*bp++ = (char)c;
		}
		*bp = '\0';
		bp = buf;
		n = 3;
		while (--n)
			while ((c = *bp++) != ':')
				if (c == '\n') {
					FUNLOCKFILE(lk);
					return (1);
				}
		while ((c = *bp++) != ':')
			if (isdigit(c))
				n = n*10+c-'0';
			else
				continue;
		if (n == uid) {
			FUNLOCKFILE(lk);
			return (0);
		}
	}
}
