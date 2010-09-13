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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Much like calloc, but with functions to report the size of the
 * allocation given only the pointer.
 */

#include <assert.h>
#include <string.h>
#include <malloc.h>
#include "sized_array.h"

/*
 * Assumes that int is at least 32 bits and that nothing needs more than
 * 8-byte alignment.
 */

/* COOKIE provides some bad-pointer protection. */
#define	COOKIE	"SACOOKIE"

struct sized_array {
	int	n;
	int	sz;
#if	defined(COOKIE)
	char	cookie[8];
#endif
};


void *
sized_array(size_t n, size_t sz)
{
	struct sized_array *sa;
	size_t total;

	total = sizeof (struct sized_array) + n*sz;

	sa = malloc(total);

	if (sa == NULL)
		return (NULL);

	(void) memset(sa, 0, total);

	sa->n = n;
	sa->sz = sz;

#if	defined(COOKIE)
	(void) memcpy(sa->cookie, COOKIE, sizeof (sa->cookie));
#endif

	return ((void *)(sa + 1));
}

void
sized_array_free(void *p)
{
	struct sized_array *sa;

	if (p == NULL)
		return;

	sa = ((struct sized_array *)p)-1;

#if	defined(COOKIE)
	assert(memcmp(sa->cookie, COOKIE, sizeof (sa->cookie)) == 0);
#endif

	free(sa);
}

size_t
sized_array_n(void *p)
{
	struct sized_array *sa;

	sa = ((struct sized_array *)p)-1;

#if	defined(COOKIE)
	assert(memcmp(sa->cookie, COOKIE, sizeof (sa->cookie)) == 0);
#endif

	return (sa->n);
}

size_t
sized_array_sz(void *p)
{
	struct sized_array *sa;

	sa = ((struct sized_array *)p)-1;

#if	defined(COOKIE)
	assert(memcmp(sa->cookie, COOKIE, sizeof (sa->cookie)) == 0);
#endif

	return (sa->sz);
}
