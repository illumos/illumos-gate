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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 */

/* $Id: list.c 146 2006-03-24 00:26:54Z njacobs $ */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*LINTLIBRARY*/

#include <stdlib.h>
#include <stdarg.h>
#include <errno.h>

static int __list_increment = 16;

int
list_append(void ***list, void *item)
{
	int count;

	if ((list == NULL) || (item == NULL)) {
		errno = EINVAL;
		return (-1);
	}

	if (item != NULL) {
		if (*list == NULL)
			*list = (void **)calloc(__list_increment,
						sizeof (void *));

		for (count = 0; (*list)[count] != NULL; count++);

		if ((count + 1) % __list_increment == 0) { /* expand the list */
			void **new_list = NULL;
			int new_size = (((count + 1) / __list_increment) + 1) *
				__list_increment;

			new_list = (void **)calloc(new_size, sizeof (void *));
			if (new_list == NULL)
				return (-1);

			for (count = 0; (*list)[count] != NULL; count++)
				new_list[count] = (*list)[count];
			free(*list);
			*list = new_list;
		}

		(*list)[count] = item;
	}

	return (0);
}

/*
 *  list_concatenate() takes in two NULL terminated lists of items (type **)
 *      and creates a new list with items from list2 appended on the end of
 *      the list of items from list1.  The result is a list (type **).  If
 *      there is a failure, -1 is returned.
 */
int
list_concatenate(void ***result, void **list2)
{
	void    **list1;
	int	size1 = 0,
		size2 = 0,
		new_size = 0;

	if ((result == NULL) || ((*result == NULL) && (list2 == NULL))) {
		errno = EINVAL;
		return (-1);
	}

	list1 = *result;

	if (list1 != NULL)
		for (size1 = 0; list1[size1] != NULL; size1++);
	if (list2 != NULL)
		for (size2 = 0; list2[size2] != NULL; size2++);

	/* list1 + list2 padded to a multiple of _list_increment */
	new_size = ((size1 + size2)/__list_increment + 2) * __list_increment;

	if ((*result = (void **)calloc((new_size), sizeof (void *)))
				!= NULL) {
		int count = 0;

		if (list1 != NULL)
			for (size1 = 0; list1[size1] != NULL; size1++)
				(*result)[count++] = list1[size1];
		if (list2 != NULL)
			for (size2 = 0; list2[size2] != NULL; size2++)
				(*result)[count++] = list2[size2];
		free(list1);
	}

	return (0);
}

/*
 *  list_locate() iterates through the list passed in and uses the comparison
 *      routine and element passed in to find an element in the list.  It
 *      returns the first element matched, or NULL if none exists
 */
void *
list_locate(void **list, int (*compare)(void *, void *), void *element)
{
	int current = 0;

	if ((list != NULL) && (element != NULL))
		for (current = 0; list[current] != NULL; current++)
			if ((compare)(list[current], element) == 0)
				return (list[current]);
	return (NULL);
}

void
list_remove(void ***list, void *item)
{
	int i, count;
	void **tmp = NULL;

	if ((list == NULL) || (*list == NULL) || (item == NULL))
		return;

	for (count = 0; (*list)[count] != NULL; count++);

	if (count > 0) {
		int new_size = (((count + 1) / __list_increment) + 1) *
				__list_increment;

		if ((tmp = (void **)calloc(new_size, sizeof (void *))) != NULL)
			tmp = *list;

		/* copy up to item */
		for (i = 0; (((*list)[i] != NULL) && ((*list)[i] != item)); i++)
			tmp[i] = (*list)[i];
		/* copy after item */
		if ((*list)[i] == item)
			for (++i; ((*list)[i] != NULL); i++)
				tmp[i-1] = (*list)[i];
	}

	/* replace the list */
	if (tmp != *list) {
		free(*list);
		*list = tmp;
	}
}
