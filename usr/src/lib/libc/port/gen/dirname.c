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
 *	Return pointer to the directory name, stripping off the last
 *	component of the path.
 *	Works similar to /bin/dirname
 */

#pragma weak _dirname = dirname

#include "lint.h"
#include <sys/types.h>
#include <string.h>

char *
dirname(char *s)
{
	char	*p;

	if (!s || !*s)			/* zero or empty argument */
		return (".");

	p = s + strlen(s);
	while (p != s && *--p == '/')	/* trim trailing /s */
		;

	if (p == s && *p == '/')
		return ("/");

	while (p != s)
		if (*--p == '/') {
			while (*p == '/' && p != s)
				p--;
			*++p = '\0';
			return (s);
		}

	return (".");
}
