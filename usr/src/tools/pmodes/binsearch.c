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
 * Copyright (c) 2000-2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * String list maintenance and binary search routines
 */


#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#define	ALLOCCHUNK	128

struct itemlist  {
    char **items;
    int nallocated;
    int nused;
    int sorted;
};

#include "binsearch.h"

itemlist
new_itemlist(void)
{
	itemlist x = malloc(sizeof (struct itemlist));

	x->nallocated = x->nused = 0;
	x->sorted = 1;
	x->items = 0;

	return (x);
}

void
item_add(itemlist l, char *s)
{
	if (l->nallocated < 0) {
		char **new;
		l->nallocated = l->nused + ALLOCCHUNK;
		new = malloc(sizeof (char *) * l->nused);
		memcpy(new, l->items, l->nused * sizeof (char *));
		l->items = new;
	} else if (l->nallocated == l->nused) {
		if (l->nallocated)
			l->nallocated *= 2;
		else
			l->nallocated = ALLOCCHUNK;
		l->items = realloc(l->items, sizeof (char *) * l->nallocated);
	}
	l->items[l->nused++] = s;
	l->sorted = l->nused <= 1;
}

void
item_add_list(itemlist l, char **s, int n, int alloc)
{
	if (l->nallocated == 0) {
		l->items = s;
		l->nallocated = alloc ? n : -1;
		l->nused = n;
		l->sorted = 0;
	} else {
		int i;

		for (i = 0; i < n; i++)
			item_add(l, s[i]);

		if (alloc)
			free(s);
	}
}

int
item_addfile(itemlist l, const char *fname)
{
	FILE *f = fopen(fname, "r");
	char buf[10240];

	if (f == NULL)
		return (-1);

	while (fgets(buf, sizeof (buf), f) != NULL) {
		if (buf[0] == '#' || buf[0] == '\n')
			continue;

		buf[strlen(buf)-1] = '\0';
		item_add(l, strdup(buf));
	}
	fclose(f);

	return (0);
}

static int
xcmp(const void *s1, const void *s2)
{
	return (strcmp(*(char **)s1, *(char **)s2));
}

int
item_search(itemlist l, const char *s)
{
	int lo = 0;
	int hi = l->nused - 1;

	if (!l->sorted) {
		qsort(l->items, l->nused, sizeof (char *), xcmp);
		l->sorted = 1;
	}

	while (lo <= hi) {
		int mid = (lo + hi) / 2;
		int res = strcmp(s, l->items[mid]);

		if (res == 0)
			return (mid);
		else if (res < 0)
			hi = mid - 1;
		else
			lo = mid + 1;
	}
	return (-1);
}

char
*item_get(itemlist l, int i)
{
	if (i >= l->nused || i < 0)
		return (NULL);
	else
		return (l->items[i]);
}
