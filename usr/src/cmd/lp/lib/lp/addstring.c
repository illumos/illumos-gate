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


#ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.3	*/

#include "string.h"
#include "errno.h"
#include "stdlib.h"

#include "lp.h"

/**
 ** addstring() - ADD ONE STRING TO ANOTHER, ALLOCATING SPACE AS NEEDED
 **/

int
#if	defined(__STDC__)
addstring (
	char **			dst,
	char *			src
)
#else
addstring (dst, src)
	char			**dst;
	char			*src;
#endif
{
	size_t			len;

	if (!dst || !src) {
		errno = EINVAL;
		return (-1);
	}

	len = strlen(src) + 1;

	if (*dst) {
		if (!(*dst = Realloc(*dst, strlen(*dst) + len))) {
			errno = ENOMEM;
			return (-1);
		}
	} else {
		if (!(*dst = Malloc(len))) {
			errno = ENOMEM;
			return (-1);
		}
		(*dst)[0] = '\0';
	}

	(void) strcat(*dst, src);
	return (0);
}
