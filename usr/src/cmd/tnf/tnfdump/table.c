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
 *	Copyright (c) 1994, by Sun Microsytems, Inc.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdlib.h>
#include <locale.h>

#include "state.h"

/*
 * This file defines routines on a table data structure. There is one
 * static table that has the following operations: insert, sort, print,
 * and get an element by index.
 */

static entry_t	*table_start = NULL;	/* start of table */
static int	table_cur = 0;		/* current size of table */
static int	table_size = 0;		/* max number of elements */

#define	GUESS_NUM_ELEM		(16 * 1024)

static void table_grow		(int);
static int timecompare		(const void *, const void *);

static void
table_grow(int num_entries)
{
	entry_t *temp;

	if (table_start == NULL) {
		table_size = num_entries;
		table_start = malloc(table_size * sizeof (struct entry));
		if (table_start == NULL)
			fail(1, gettext("malloc:"));
		return;
	}
	table_size += num_entries;
	temp = realloc(table_start, table_size * sizeof (struct entry));
	if (temp == NULL)
		fail(1, gettext("realloc:"));
	table_start = temp;
}

static int
timecompare(const void *i, const void *j)
{
	hrtime_t	result;

	result = ((entry_t *)i)->time - ((entry_t *)j)->time;
	if (result < (longlong_t) 0)
		return (-1);
	else if (result == (longlong_t) 0)
		return (0);
	else
		return (1);
}

/*
 * insert an entry into the table.  Automatically grows it if needed
 */
void
table_insert(entry_t *element)
{
	if (table_cur >= table_size) {
		table_grow(GUESS_NUM_ELEM);
	}
	/* copy the structure to the array, increment cur index */
	table_start[table_cur++] = *element;
}

int
table_get_num_elements(void)
{
	return (table_size);
}

void
table_sort(void)
{
	qsort(table_start, table_cur, sizeof (struct entry), &timecompare);
}

void
table_print(void (*print_elem)(entry_t *))
{
	int i;

	for (i = 0; i < table_cur; i++) {
		print_elem(&(table_start[i]));
	}
}

entry_t *
table_get_entry_indexed(int n)
{
	if (n < table_cur)
		return (&(table_start[n]));
	return (NULL);
}
