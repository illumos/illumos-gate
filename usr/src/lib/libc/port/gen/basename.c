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
 *	Return pointer to the last element of a pathname.
 */

#pragma weak _basename = basename

#include "lint.h"
#include <libgen.h>
#include <string.h>
#include <sys/types.h>

char *
basename(char *s)
{
	char	*p;

	if (!s || !*s)			/* zero or empty argument */
		return (".");

	p = s + strlen(s);
	while (p != s && *--p == '/')	/* skip trailing /s */
		*p = '\0';

	if (p == s && *p == '\0')		/* all slashes */
		return ("/");

	while (p != s)
		if (*--p == '/')
			return (++p);

	return (p);
}
