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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Copyright (c) 1994, 2000 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#include "med_local.h"

/*
 * free
 */
void
Free(
	void	*p
)
{
	free(p);
}

/*
 * malloc
 */
void *
Malloc(
	size_t	s
)
{
	void *mem;

	if ((mem = malloc(s)) == NULL) {
		med_perror("");
		med_exit(1);
	}
	return (mem);
}

/*
 * zalloc
 */
void *
Zalloc(
	size_t	s
)
{
	return (memset(Malloc(s), 0, s));
}

/*
 * realloc
 */
void *
Realloc(
	void	*p,
	size_t	s
)
{
	if ((p = realloc(p, s)) == NULL) {
		med_perror("");
		med_exit(1);
	}
	return (p);
}

/*
 * calloc
 */
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

/*
 * strdup
 */
char *
Strdup(
	char	*p
)
{
	if ((p = strdup(p)) == NULL) {
		med_perror("");
		med_exit(1);
	}
	return (p);
}
