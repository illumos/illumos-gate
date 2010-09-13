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

/*
 * Copyright (c) 1994, 2000 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "mhd_local.h"

void
Free(
	void	*p
)
{
	free(p);
}

void *
Malloc(
	size_t	s
)
{
	void *mem;

	if ((mem = malloc(s)) == NULL) {
		mhd_perror("");
		mhd_exit(1);
	}
	return (mem);
}

void *
Zalloc(
	size_t	s
)
{
	return (memset(Malloc(s), 0, s));
}

void *
Realloc(
	void	*p,
	size_t	s
)
{
	if (p == NULL)
		p = malloc(s);
	else
		p = realloc(p, s);
	if (p == NULL) {
		mhd_perror("");
		mhd_exit(1);
	}
	return (p);
}

void *
Calloc(
	size_t	n,
	size_t	s
)
{
	unsigned long total;

	if (n == 0 || s == 0) {
		total = 0;
	} else {
		total = (unsigned long)n * s;
		/* check for overflow */
		if (total / n != s)
			return (NULL);
	}
	return (Zalloc(total));
}

char *
Strdup(
	const char	*p
)
{
	char		*n;

	if ((n = strdup(p)) == NULL) {
		mhd_perror("");
		mhd_exit(1);
	}
	return (n);
}
