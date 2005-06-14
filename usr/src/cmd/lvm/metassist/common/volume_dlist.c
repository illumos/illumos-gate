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
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

#include "volume_dlist.h"

#define	_volume_dlist_C

/*
 * public constant definitions
 */
const	boolean_t	ASCENDING	= TRUE;	/* list ordering */
const	boolean_t	DESCENDING	= FALSE;
const	boolean_t	AT_TAIL		= TRUE;	/* list insertion location */
const	boolean_t	AT_HEAD		= FALSE;

/*
 * determine if the list contains an item
 * that points at the object
 */
boolean_t
dlist_contains(
	dlist_t  *list,
	void	 *obj,
	int	(compare)(void *, void *))
{
	return (dlist_find(list, obj, compare) != NULL);
}

/*
 * locate the item in the list that points at the object
 */
dlist_t *
dlist_find(
	dlist_t  *list,
	void	 *obj,
	int	(compare)(void *, void *))
{
	dlist_t  *iter;

	for (iter = list; iter != NULL; iter = iter->next) {
	    if ((compare)(obj, iter->obj) == 0) {
		return (iter);
	    }
	}

	return (NULL);
}

/*
 * insert item into list in the desired order (ascending or descending)
 * using the comparison function provided.
 *
 * In the for loop, iter marks current position in the list
 * and item is the item to be inserted.
 *
 * Iterate the list and find the correct place to insert temp.
 *
 * if (ascending && compare(item, iter) <= 0 ||
 *    (descending && compare(item, iter) >= 0)
 *     item goes before iter
 * else
 *     item goes after iter
 */
dlist_t *
dlist_insert_ordered(
	dlist_t	*item,
	dlist_t	*list,
	boolean_t	ascending,
	int	(compare)(void *, void *))
{
	dlist_t	*head   = NULL;
	dlist_t	*iter   = NULL;
	int	result = 0;

	if (list == NULL) {

	    head = item;

	} else {

	    head = list;

	    for (iter = list; iter != NULL; iter = iter->next) {

		result = (compare)(item->obj, iter->obj);

		if ((ascending && (result <= 0)) ||
			(!ascending && (result >= 0))) {

		    if (iter == head) {
			head = item;
			item->next = iter;
			iter->prev = item;
		    } else {
			item->prev = iter->prev;
			item->prev->next = item;
			iter->prev = item;
			item->next = iter;
		    }
		    break;
		}

		if (iter->next == NULL) {
		    /* end of list, so item becomes the new end */
		    iter->next = item;
		    item->prev = iter;
		    break;
		}
	    }
	}

	return (head);
}

/*
 * Remove the first node pointing to same content as item from list,
 * clear it's next and prev pointers, return new list head.
 *
 * The caller is responsible for freeing the removed item if it is no
 * longer needed.
 *
 * The comparison function should be of the form:
 *
 *     int compare(void *obj1, void* obj2);
 *
 * When called, obj1 will be the object passed into
 * dlist_remove_equivalent_item and obj2 will be an object pointed to
 * by an item in the list.
 *
 * The function should return 0 if the two objects are equivalent The
 * function should return nonzero otherwise
 *
 * @param       list
 *              the list containing the item to remove
 *
 * @param       obj
 *              the object with which to compare each item
 *
 * @param       compare
 *              the comparison function, passed obj and the obj member
 *              of each item, to return 0 if item should be removed
 *
 * @param       removed
 *              RETURN: the removed item, or NULL if none was found
 *
 * @return      the first element of the resulting list
 */
dlist_t *
dlist_remove_equivalent_item(
	dlist_t	*list,
	void	*obj,
	int	(compare)(void *, void *),
	dlist_t **removed)
{
	dlist_t	*item;

	*removed = NULL;

	if (list == NULL) {
	    return (list);
	}

	item = dlist_find(list, obj, compare);
	if (item == NULL) {
	    return (list);
	}

	*removed = item;

	return (dlist_remove(item));
}

/*
 * Remove an item from its list.  Return the resulting list.
 *
 * @param       item
 *              the item to remove, with prev and next pointers
 *              set to NULL
 *
 * @return      the first element of the resulting list
 */
dlist_t *
dlist_remove(
	dlist_t	*item)
{
	dlist_t *head = NULL;

	if (item != NULL) {
	    if (item->next != NULL) {
		item->next->prev = item->prev;
		head = item->next;
	    }

	    if (item->prev != NULL) {
		item->prev->next = item->next;
		head = item->prev;
	    }

	    item->next = NULL;
	    item->prev = NULL;

	    /* Find head of list */
	    for (; head != NULL && head->prev != NULL; head = head->prev);
	}

	return (head);
}

/*
 * append item to list, either beginning or end
 */
dlist_t *
dlist_append(
	dlist_t	*item,
	dlist_t	*list,
	boolean_t	attail)
{
	dlist_t	*head = list;

	if (list == NULL) {

	    head = item;

	} else if (item == NULL) {

	    head = list;

	} else if (attail) {

	    dlist_t *iter;

	    /* append to end */
	    for (iter = head; iter->next != NULL; iter = iter->next);

	    iter->next = item;
	    item->prev = iter;

	} else {
	    /* insert at begining */
	    item->next = head;
	    head->prev = item;
	    head = item;
	}

	return (head);
}

/*
 * Create a dlist_t element for the given object and append to list.
 *
 * @param       object
 *              the obj member of the dlist_t element to be created
 *
 * @param       list
 *              the list to which to append the new dlist_t element
 *
 * @param       attail
 *              whether to append at the beginning (AT_HEAD) or end
 *              (AT_TAIL) of the list
 *
 * @return      0
 *              if successful
 *
 * @return      ENOMEM
 *              if a dlist_t could not be allocated
 */
int
dlist_append_object(
	void *object,
	dlist_t **list,
	boolean_t attail)
{
	dlist_t *item = dlist_new_item(object);

	if (item == NULL) {
	    return (ENOMEM);
	}

	*list = dlist_append(item, *list, attail);

	return (0);
}

/*
 * Appends list2 to the end of list1.
 *
 * Returns the resulting list.
 */
dlist_t *
dlist_append_list(
	dlist_t *list1,
	dlist_t *list2)
{
	dlist_t *iter;

	if (list1 == NULL) {
	    return (list2);
	}

	if (list2 != NULL) {
	    /* Find last element of list1 */
	    for (iter = list1; iter->next != NULL; iter = iter->next);

	    iter->next = list2;
	    list2->prev = iter;
	}

	return (list1);
}

/*
 * compute number of items in list
 */
int
dlist_length(
	dlist_t	*list)
{
	dlist_t	*iter;
	int	length = 0;

	for (iter = list; iter != NULL; iter = iter->next)
	    ++length;

	return (length);
}

/*
 * Allocate a new dlist_t structure and initialize the opaque object
 * pointer the input object.
 *
 * @return      A new dlist_t structure for the given object, or NULL
 *              if the memory could not be allocated.
 */
dlist_t *
dlist_new_item(
	void	*obj)
{
	dlist_t	*item = (dlist_t *)calloc(1, sizeof (dlist_t));

	if (item != NULL) {
	    item->obj = obj;
	}

	return (item);
}

/*
 * Traverse the list pointed to by head and free each
 * list node.  If freefunc is non-NULL, call freefunc
 * for each node's object.
 */
void
dlist_free_items(
	dlist_t	*head,
	void (freefunc(void *)))
{
	while (head != NULL) {
	    dlist_t *item = head;
	    head = head->next;

	    if (freefunc != NULL) {
		freefunc(item->obj);
	    }

	    free((void *) item);
	}
}

/*
 * Order the given list such that the number of similar elements
 * adjacent to each other are minimized.
 *
 * The algorithm is:
 *
 * 1. Sort similar items into categories.  Two elements are considered
 *    similar if the given compare function returns 0.
 *
 * 2. Create a new list by iterating through each category and
 *    selecting an element from the category with the most elements.
 *    Avoid choosing an element from the last category chosen.
 *
 * @param       list
 *              the list to order
 *
 * @param       compare
 *              the comparison function, passed the obj members
 *              of two items, to return 0 if the items can be
 *              considered similar
 *
 * @return      the first element of the resulting list
 */
dlist_t *
dlist_separate_similar_elements(
	dlist_t *list,
	int(compare)(void *, void *))
{
	dlist_t **categories = NULL;
	dlist_t *item;
	int ncategories = 0;
	int max_elements;
	int lastcat;

	/*
	 * First, sort like items into categories, according to
	 * the passed-in compare function
	 */
	for (item = list; item != NULL; ) {
	    dlist_t *removed;

	    /* Remove this item from the list */
	    list = dlist_remove(item);

	    /* Create new category */
	    categories = (dlist_t **)realloc(
		categories, ++ncategories * sizeof (dlist_t *));
	    categories[ncategories - 1] = item;

	    /* Add like items to same category */
	    list = dlist_remove_equivalent_item(
		list, item->obj, compare, &removed);
	    while (removed != NULL) {
		/* Add removed item to category */
		dlist_append(removed, item, AT_TAIL);
		list = dlist_remove_equivalent_item(
		    list, item->obj, compare, &removed);
	    }

	    item = list;
	}

	/*
	 * Next, create a new list, minimizing the number of adjacent
	 * elements from the same category
	 */
	list = NULL;
	lastcat = -1;
	do {
	    int i;
	    int curcat;

		/*
		 * Find the category with the most elements, other than
		 * the last category chosen
		 */
	    max_elements = 0;
	    for (i = 0; i < ncategories; i++) {
		int nelements;

		if (i == lastcat) {
		    continue;
		}

		nelements = dlist_length(categories[i]);
		if (nelements > max_elements) {
		    max_elements = nelements;
		    curcat = i;
		}
	    }

	    /* If no elements were found, use the last category chosen */
	    if (max_elements == 0 && lastcat >= 0) {
		max_elements = dlist_length(categories[lastcat]);
		curcat = lastcat;
	    }

	    /* Was a category with elements found? */
	    if (max_elements != 0) {
		/* Remove first element of chosen category */
		item = categories[curcat];
		categories[curcat] = dlist_remove(item);

		/* Add removed element to resulting list */
		list = dlist_append(item, list, AT_TAIL);

		lastcat = curcat;
	    }
	} while (max_elements != 0);

	free(categories);

	return (list);
}
