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

/*	Copyright (c) 1988 AT&T */
/*	  All Rights Reserved	*/

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "lint.h"
#include "mtlib.h"
#include <sys/types.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <thread.h>
#include <synch.h>
#include "tsd.h"

static char seed[] = { 'a', 'a', 'a', '\0' };

static mutex_t seed_lk = DEFAULTMUTEX;

char *
tmpnam_r(char *s)
{
	char *p = s, *q;

	if (!s)
		return (NULL);

	(void) strcpy(p, P_tmpdir);
	lmutex_lock(&seed_lk);
	(void) strcat(p, seed);
	(void) strcat(p, "XXXXXX");

	q = seed;
	while (*q == 'z')
		*q++ = 'a';
	if (*q != '\0')
		++*q;
	lmutex_unlock(&seed_lk);
	(void) mktemp(p);
	return (p);
}

char *
tmpnam(char *s)
{
	if (s == NULL)
		s = tsdalloc(_T_TMPNAM, L_tmpnam, NULL);
	return (tmpnam_r(s));
}
