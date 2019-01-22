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
 */

/*LINTLIBRARY*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <stdarg.h>
#include <syslog.h>
#include <stdlib.h>
#include <strings.h>

#include <list.h>


static int _list_increment = 64;  /* just so It can be tuned with adb(1) */
/*
 *  list_append() takes in a list (type **) and a pointer to an item to add
 *	to the list and returns a new list with the new item appended on the
 *	end.  The list is NULL terminated.  If there was an error, NULL is
 *	returned.  For reasonable efficiency, the list will be allocated
 *	in blocks of size _list_increment.
 */
void **
list_append(void **list, void *item)
{
#ifdef DEBUG
	syslog(LOG_DEBUG, "list_append(0x%x, 0x%x)", list, item);
#endif
	if (item == NULL)
		return (list);

	if (list == NULL) {
		list = (void **)calloc(_list_increment, sizeof (void *));
		if (list != NULL)
			list[0] = item;
	} else {
		int count;

		for (count = 0; list[count] != NULL; count++)
			;

		if ((count + 1) % _list_increment == 0) { /* increase size */
			void **new_list = NULL;
			int new_size = (((count + 1) / _list_increment) + 1) *
			    _list_increment;

			new_list = (void **)calloc(new_size, sizeof (void *));
			if (new_list == NULL)
				return (NULL);
			for (count = 0; list[count] != NULL; count++)
				new_list[count] = list[count];
			free(list);
			list = new_list;
		}
		list[count] = item;
	}
	return (list);
}


void **
list_append_unique(void **list, void *item, int (*cmp)(void *, void*))
{
	if (list_locate(list, cmp, item))
		return (list);

	list = list_append(list, item);
	return (list);
}


/*
 *  list_locate() iterates through the list passed in and uses the comparison
 *	routine and element passed in to find an element in the list.  It
 *	returns the first element matched, or NULL if none exists
 */
void *
list_locate(void **list, int (*compair)(void *, void *), void *element)
{
	int	current = 0;

#ifdef DEBUG
	syslog(LOG_DEBUG, "list_locate()");
#endif
	if (list != NULL)
		for (current = 0; list[current] != NULL; current++)
			if ((compair)(list[current], element) == 0)
				return (list[current]);
	return (NULL);
}


/*
 *  list_concatenate() takes in two NULL terminated lists of items (type **)
 *	and creates a new list with items from list2 appended on the end of
 *	the list of items from list1.  The result is a list (type **).  If
 *	there is a failure, NULL is returned.
 */
void **
list_concatenate(void **list1, void **list2)
{
	void **list = NULL;
	int size1 = 0, size2 = 0, new_size = 0;
#ifdef DEBUG
	syslog(LOG_DEBUG, "list_concatenate(0x%x, 0x%x)", list1, list2);
#endif
	if ((list1 == NULL) || (list2 == NULL))
		return ((list1 != NULL) ? list1 : list2);

	for (size1 = 0; list1[size1] != NULL; size1++)
		;
	for (size2 = 0; list2[size2] != NULL; size2++)
		;

	/* list1 + list2 padded to a multiple of _list_increment */
	new_size = ((size1 + size2)/_list_increment + 2) * _list_increment;

	if ((list = (void **)calloc((new_size), sizeof (void *))) != NULL) {
		int count = 0;

		for (size1 = 0; list1[size1] != NULL; size1++)
			list[count++] = list1[size1];
		for (size2 = 0; list2[size2] != NULL; size2++)
			list[count++] = list2[size2];
		free(list1);
	}
	return (list);
}


/*
 *  list_iterate() take in a list, pointer to a function, and variable number
 *	of arguements following.  list_iterate() will iterate through the list
 *	calling the functions passed in with the first argument being a pointer
 *	to the current item in the list and the second argument being a va_list
 *	containing the rest of arguments used to call list_iterate().  The
 *	calling fuction should be declared: int func(type *, va_list).  The
 *	return results are all added together and the sum is returned from
 *	list_iterate().
 */
int
list_iterate(void **list, int (*vfunc)(void *, va_list), ...)
{
	int current = 0, rc = 0;

#ifdef DEBUG
	syslog(LOG_DEBUG, "list_iterate(0x%x, 0x%x)", list, vfunc);
#endif
	if (list != NULL)
		while (list[current] != NULL) {
			va_list	ap;

			va_start(ap, (vfunc));
			rc += (vfunc)(list[current++], ap);
			va_end(ap);
		}
	return (rc);
}
