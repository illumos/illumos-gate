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

#pragma weak _tempnam = tempnam

#include "lint.h"
#include <mtlib.h>
#include <sys/types.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <thread.h>
#include <synch.h>
#include <unistd.h>
#include <sys/stat.h>

#define	max(A, B) (((A) < (B))?(B):(A))

static char *pcopy(char *, const char *);

static char seed[] = "AAA";

static mutex_t seed_lk = DEFAULTMUTEX;

char *
tempnam(const char *dir,	/* use this directory please (if non-NULL) */
	const char *pfx)	/* use this (if non-NULL) as filename prefix */
{
	char *p, *q, *tdir;
	size_t x = 0, y = 0, z;
	struct stat64 statbuf;

	z = sizeof (P_tmpdir) - 1;
	if ((tdir = getenv("TMPDIR")) != NULL) {
		x = strlen(tdir);
	}
	if (dir != NULL) {
		if (stat64(dir, &statbuf) == 0 && S_ISDIR(statbuf.st_mode))
			y = strlen(dir);
	}
	if ((p = malloc(max(max(x, y), z)+16)) == NULL)
		return (NULL);
	if (x > 0 && access(pcopy(p, tdir), (W_OK | X_OK)) == 0)
		goto OK;
	if (y > 0 && access(pcopy(p, dir), (W_OK | X_OK)) == 0)
		goto OK;
	if (access(pcopy(p, P_tmpdir), (W_OK | X_OK)) == 0)
		goto OK;
	if (access(pcopy(p, "/tmp"), (W_OK | X_OK)) != 0) {
		free(p);
		return (NULL);
	}
OK:
	(void) strcat(p, "/");
	if (pfx) {
		*(p+strlen(p)+5) = '\0';
		(void) strncat(p, pfx, 5);
	}
	lmutex_lock(&seed_lk);
	(void) strcat(p, seed);
	(void) strcat(p, "XXXXXX");
	q = seed;
	while (*q == 'Z')
		*q++ = 'A';
	if (*q != '\0')
		++*q;
	lmutex_unlock(&seed_lk);
	if (*mktemp(p) == '\0') {
		free(p);
		return (NULL);
	}
	return (p);
}

static char *
pcopy(char *space, const char *arg)
{
	char *p;

	if (arg) {
		(void) strcpy(space, arg);
		p = space-1+strlen(space);
		while ((p >= space) && (*p == '/'))
			*p-- = '\0';
	}
	return (space);
}
