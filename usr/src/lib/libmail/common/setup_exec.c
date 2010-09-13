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

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <ctype.h>
#include "libmail.h"

#define	TRUE	1
#define	FALSE	0

char **
setup_exec(char *s)
{
	char	*p = s, *q;
	static char	*argvec[256]; /* is this enough? */
	int	i = 0;
	int	stop;
	int	ignorespace = FALSE;

	/* Parse up string into arg. vec. for subsequent exec. Assume */
	/* whitespace delimits args. Any non-escaped double quotes will */
	/* be used to group multiple whitespace-delimited tokens into */
	/* a single exec arg. */
	p = skipspace(p);
	while (*p) {
		q = p;
		stop = FALSE;
		while (*q && (stop == FALSE)) {
		again:
			switch (*q) {
			case '\\':
				/* Slide command string 1 char to left */
				strmove(q, q+1);
				break;
			case '"':
				ignorespace = ((ignorespace == TRUE) ?
				    FALSE : TRUE);
				/* Slide command string 1 char to left */
				strmove(q, q+1);
				goto again;
			default:
				if (isspace((int)*q) &&
				    (ignorespace == FALSE)) {
					stop = TRUE;
					continue;
				}
				break;
			}
			q++;
		}
		if (*q == '\0') {
			argvec[i++] = p;
			break;
		}
		*q++ = '\0';
		argvec[i++] = p;
		p = skipspace(q);
	}
	argvec[i] = NULL;
	if (i == 0) {
		return (NULL);
	}
	return (argvec);
}
