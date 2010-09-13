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

#ifndef _VOLUME_DLIST_H
#define	_VOLUME_DLIST_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/types.h>

/*
 * Structure defining a doubly linked list of arbitrary objects
 */
typedef struct dlist {

    struct dlist	*next;
    struct dlist	*prev;
    void		*obj;

} dlist_t;

/*
 * module globals
 */
extern const boolean_t ASCENDING;
extern const boolean_t DESCENDING;
extern const boolean_t AT_TAIL;
extern const boolean_t AT_HEAD;

/* from types.h */
#ifndef TRUE
#define	TRUE	B_TRUE
#endif

#ifndef FALSE
#define	FALSE	B_FALSE
#endif

/*
 * doubly linked list utility methods
 */

/*
 * count the number of elements currently in the list
 */
extern int	 dlist_length(dlist_t *list);

/*
 * Traverse the list pointed to by head and free each
 * list node.  If freefunc is non-NULL, call freefunc
 * for each node's object.
 */
extern void	dlist_free_items(dlist_t *list, void (freefunc(void *)));

/*
 * append item to list.  If atend is true, the item is
 * added at the end of the list, otherwise it is added
 * at the beginning.
 *
 * returns the possibly changed head of the list.
 */
extern dlist_t	*dlist_append(
	dlist_t	*item,
	dlist_t	*list,
	boolean_t atend);

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
extern int dlist_append_object(
	void *object,
	dlist_t **list,
	boolean_t attail);

/*
 * Appends list2 to the end of list1.
 *
 * Returns the resulting list.
 */
extern dlist_t *dlist_append_list(
	dlist_t *list1,
	dlist_t *list2);

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
 * dlist_remove_equivalent_item and obj2 will be an object pointed to by an
 * item in the list.
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
extern dlist_t	*dlist_remove_equivalent_item(
	dlist_t *list,
	void	*obj,
	int	(compare)(void *obj1, void *obj2),
	dlist_t **removed);

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
	dlist_t	*item);

/*
 * allocates memory for a new list item.  The list item will
 * point at obj.
 *
 * returns the new list item.
 */
extern dlist_t	*dlist_new_item(void *obj);

/*
 * inserts item in the correct position within the list based on
 * the comparison function.  if ascending is true, the list will
 * be in ascending order, otherwise descending.
 *
 * the comparison function should be of the form:
 *
 *     int compare(void *obj1, void *obj2);
 *
 * When called, obj1 will be the object pointed to by the item to
 * be added to the list, obj2 will be an object pointed to by an
 * item currently in the list.
 *
 * The function should return 0 if the two objects are equivalent
 * The function should return <0 if obj1 comes before obj2
 * The function should return >0 if obj1 comes after obj2
 *
 * dlist_insert_ordered returns the possibly changed head
 * of the list.
 */
extern dlist_t	*dlist_insert_ordered(
	dlist_t	*item,
	dlist_t	*list,
	boolean_t	ascending,
	int	(compare)(void *obj1, void *obj2));

/*
 * Locates the item in the list which contains object.
 *
 * the comparison function should be of the form:
 *
 *     int compare(void *obj1, void *obj2);
 *
 * When called, obj1 will be the input object, obj2 will be
 * an object pointed to by an item currently in the list.
 *
 * The function should return 0 if the two objects are equivalent
 * The function should return non-zero otherwise
 *
 * dlist_find() returns the found item or NULL if one was not found.
 */
extern dlist_t	*dlist_find(
	dlist_t *list,
	void	*obj,
	int	(compare)(void *obj1, void *obj2));

/*
 * Determines if list has an item which contains object.
 *
 * the comparison function should be of the form:
 *
 *     int compare(void *obj1, void *obj2);
 *
 * When called, obj1 will be the input object, obj2 will be
 * an object pointed to by an item currently in the list.
 *
 * The function should return 0 if the two objects are equivalent
 * The function should return non-zero otherwise
 *
 * dlist_contains() returns TRUE if the object is already
 * in the list or FALSE otherwise.
 */
extern boolean_t	dlist_contains(
	dlist_t *list,
	void	*obj,
	int	(compare)(void *obj1, void *obj2));

/*
 * Order the given list such that the number of similar elements
 * adjacent to each other are minimized.  Two elements are considered
 * similar if the given compare function returns 0.
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
extern dlist_t *
dlist_separate_similar_elements(
	dlist_t *list,
	int(*equals)(void *, void *));

#ifdef __cplusplus
}
#endif

#endif /* _VOLUME_DLIST_H */
