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
#include <sgs.h>
#include <string.h>
#include <stdio.h>
#include <sys/debug.h>

/*
 * Alist manipulation.  An Alist is a list of elements formed into an array.
 * Traversal of the list is an array scan, which because of the locality of
 * each reference is probably more efficient than a link-list traversal.
 *
 * See alist.h for more background information about array lists.
 */

/*
 * Insert a value into an array at a specified index:
 *
 *	alist_insert(): Insert an item into an Alist at the specified index
 *	alist_insert_by_offset(): Insert an item into an Alist at the
 *		specified offset relative to the list address.
 *	aplist_insert() Insert a pointer into an APlist at the specified index
 *
 * entry:
 *	Note: All the arguments for all three routines are listed here.
 *	The routine to which a given argument applies is given with
 *	each description.
 *
 *	llp [all] - Address of a pointer to an Alist/APlist. The pointer should
 *		be initialized to NULL before its first use.
 *	datap [alist_insert / aplist_insert] - Pointer to item data, or
 *		NULL. If non-null the data referenced is copied into the
 *		Alist item. Otherwise, the list item is zeroed, and
 *		further initialization is left to the caller.
 *	ptr [aplist_insert] - Pointer to be inserted.
 *	size [alist_insert / alist_insert_by_offset] - Size of an item
 *		in the array list, in bytes. As with any array, A given
 *		Alist can support any item size, but every item in that
 *		list must have the same size.
 *	init_arritems [all] - Initial allocation size: On the first insertion
 *		into the array list, room for init_arritems items is allocated.
 *	idx [alist_insert / aplist_insert] - Index at which to insert the
 *		new item. This index must lie within the existing list,
 *		or be the next index following.
 *	off [alist_insert_by_offset] - Offset at which  to insert the new
 *		item, based from the start of the Alist. The offset of
 *		the first item is ALIST_OFF_DATA.
 *
 * exit:
 *	The item is inserted at the specified position. This operation
 *	can cause memory for the list to be allocated, or reallocated,
 *	either of which will cause the value of the list pointer
 *	to change.
 *
 *	These routines can only fail if unable to allocate memory,
 *	in which case NULL is returned.
 *
 *	If a pointer list (aplist_insert), then the pointer
 *	is stored in the requested index. On success, the address
 *	of the pointer within the list is returned.
 *
 *	If the list contains arbitrary data (not aplist_insert): If datap
 *	is non-NULL, the data it references is copied into the item at
 *	the index. If datap is NULL, the specified item is zeroed.
 *	On success, a pointer to the inserted item is returned.
 *
 *	The  caller must not retain the returned pointer from this
 *	routine across calls to the list module. It is only safe to use
 *	it until the next call to this module for the given list.
 *
 */
void *
alist_insert(Alist **lpp, const void *datap, size_t size,
    Aliste init_arritems, Aliste idx)
{
	Alist	*lp = *lpp;
	char	*addr;

	/* The size and initial array count need to be non-zero */
	ASSERT(init_arritems != 0);
	ASSERT(size != 0);

	if (lp == NULL) {
		Aliste bsize;

		/*
		 * First time here, allocate a new Alist.  Note that the
		 * Alist al_desc[] entry is defined for 1 element,
		 * but we actually allocate the number we need.
		 */
		bsize = size * init_arritems;
		bsize = S_ROUND(bsize, sizeof (void *));
		bsize = ALIST_OFF_DATA + bsize;
		if ((lp = malloc((size_t)bsize)) == NULL)
			return (NULL);
		lp->al_arritems = init_arritems;
		lp->al_nitems = 0;
		lp->al_next = ALIST_OFF_DATA;
		lp->al_size = size;
		*lpp = lp;
	} else {
		/* We must get the same value for size every time */
		ASSERT(size == lp->al_size);

		if (lp->al_nitems >= lp->al_arritems) {
			/*
			 * The list is full: Increase the memory allocation
			 * by doubling it.
			 */
			Aliste	bsize;

			bsize = lp->al_size * lp->al_arritems * 2;
			bsize = S_ROUND(bsize, sizeof (void *));
			bsize = ALIST_OFF_DATA + bsize;
			if ((lp = realloc((void *)lp, (size_t)bsize)) == 0)
				return (NULL);
			lp->al_arritems *= 2;
			*lpp = lp;
		}
	}

	/*
	 * The caller is not supposed to use an index that
	 * would introduce a "hole" in the array.
	 */
	ASSERT(idx <= lp->al_nitems);

	addr = (idx * lp->al_size) + (char *)lp->al_data;

	/*
	 * An appended item is added to the next available array element.
	 * An insert at any other spot requires that the data items that
	 * exist at the point of insertion be shifted down to open a slot.
	 */
	if (idx < lp->al_nitems)
		(void) memmove(addr + lp->al_size, addr,
		    (lp->al_nitems - idx) * lp->al_size);

	lp->al_nitems++;
	lp->al_next += lp->al_size;
	if (datap != NULL)
		(void) memcpy(addr, datap, lp->al_size);
	else
		(void) memset(addr, 0, lp->al_size);
	return (addr);
}

void *
alist_insert_by_offset(Alist **lpp, const void *datap, size_t size,
    Aliste init_arritems, Aliste off)
{
	Aliste idx;

	if (*lpp == NULL) {
		ASSERT(off == ALIST_OFF_DATA);
		idx = 0;
	} else {
		idx = (off - ALIST_OFF_DATA) / (*lpp)->al_size;
	}

	return (alist_insert(lpp, datap, size, init_arritems, idx));
}

void *
aplist_insert(APlist **lpp, const void *ptr, Aliste init_arritems, Aliste idx)
{
	APlist	*lp = *lpp;

	/* The initial array count needs to be non-zero */
	ASSERT(init_arritems != 0);

	if (lp == NULL) {
		Aliste bsize;

		/*
		 * First time here, allocate a new APlist.  Note that the
		 * APlist apl_desc[] entry is defined for 1 element,
		 * but we actually allocate the number we need.
		 */
		bsize = APLIST_OFF_DATA + (sizeof (void *) * init_arritems);
		if ((lp = malloc((size_t)bsize)) == NULL)
			return (NULL);
		lp->apl_arritems = init_arritems;
		lp->apl_nitems = 0;
		*lpp = lp;
	} else if (lp->apl_nitems >= lp->apl_arritems) {
		/*
		 * The list is full: Increase the memory allocation
		 * by doubling it.
		 */
		Aliste	bsize;

		bsize = APLIST_OFF_DATA +
		    (2 * sizeof (void *) * lp->apl_arritems);
		if ((lp = realloc((void *)lp, (size_t)bsize)) == 0)
			return (NULL);
		lp->apl_arritems *= 2;
		*lpp = lp;
	}

	/*
	 * The caller is not supposed to use an index that
	 * would introduce a "hole" in the array.
	 */
	ASSERT(idx <= lp->apl_nitems);

	/*
	 * An appended item is added to the next available array element.
	 * An insert at any other spot requires that the data items that
	 * exist at the point of insertion be shifted down to open a slot.
	 */
	if (idx < lp->apl_nitems)
		(void) memmove((char *)&lp->apl_data[idx + 1],
		    (char *)&lp->apl_data[idx],
		    (lp->apl_nitems - idx) * sizeof (void *));

	lp->apl_nitems++;
	lp->apl_data[idx] = (void *)ptr;
	return (&lp->apl_data[idx]);
}

/*
 * Append a value to a list. These are convenience wrappers on top
 * of the insert operation. See the description of those routine above
 * for details.
 */
void *
alist_append(Alist **lpp, const void *datap, size_t size,
    Aliste init_arritems)
{
	Aliste ndx = ((*lpp) == NULL) ? 0 : (*lpp)->al_nitems;

	return (alist_insert(lpp, datap, size, init_arritems, ndx));
}

void *
aplist_append(APlist **lpp, const void *ptr, Aliste init_arritems)
{
	Aliste ndx = ((*lpp) == NULL) ? 0 : (*lpp)->apl_nitems;

	return (aplist_insert(lpp, ptr, init_arritems, ndx));
}

/*
 * Delete the item at a specified index/offset, and decrement the variable
 * containing the index:
 *
 *	alist_delete - Delete an item from an Alist at the specified
 *		index.
 *	alist_delete_by_offset - Delete an item from an Alist at the
 *		specified offset from the list pointer.
 *	aplist_delete - Delete a pointer from an APlist at the specified
 *		index.
 *
 * entry:
 *	alp - List to delete item from
 *	idxp - Address of variable containing the index of the
 *		item to delete.
 *	offp - Address of variable containing the offset of the
 *		item to delete.
 *
 * exit:
 *	The item at the position given by (*idxp) or (*offp), depending
 *	on the routine, is removed from the list. Then, the position
 *	variable (*idxp or *offp) is decremented by one item. This is done
 *	to facilitate use of this routine within a TRAVERSE loop.
 *
 * note:
 *	Deleting the last element in an array list is cheap, but
 *	deleting any other item causes a memory copy to occur to
 *	move the following items up. If you intend to traverse the
 *	entire list, deleting every item as you go, it will be cheaper
 *	to omit the delete within the traverse, and then call
 *	the reset function reset() afterwards.
 */
void
alist_delete(Alist *lp, Aliste *idxp)
{
	Aliste	idx = *idxp;


	/* The list must be allocated and the index in range */
	ASSERT(lp != NULL);
	ASSERT(idx < lp->al_nitems);

	/*
	 * If the element to be removed is not the last entry of the array,
	 * slide the following elements over the present element.
	 */
	if (idx < --lp->al_nitems) {
		char *addr = (idx * lp->al_size) + (char *)lp->al_data;

		(void) memmove(addr, addr + lp->al_size,
		    (lp->al_nitems - idx) * lp->al_size);
	}
	lp->al_next -= lp->al_size;

	/* Decrement the callers index variable */
	(*idxp)--;
}

void
alist_delete_by_offset(Alist *lp, Aliste *offp)
{
	Aliste idx;

	ASSERT(lp != NULL);
	idx = (*offp - ALIST_OFF_DATA) / lp->al_size;

	alist_delete(lp, &idx);
	*offp -= lp->al_size;
}

void
aplist_delete(APlist *lp, Aliste *idxp)
{
	Aliste	idx = *idxp;


	/* The list must be allocated and the index in range */
	ASSERT(lp != NULL);
	ASSERT(idx < lp->apl_nitems);

	/*
	 * If the element to be removed is not the last entry of the array,
	 * slide the following elements over the present element.
	 */
	if (idx < --lp->apl_nitems)
		(void) memmove(&lp->apl_data[idx], &lp->apl_data[idx + 1],
		    (lp->apl_nitems - idx) * sizeof (void *));

	/* Decrement the callers index variable */
	(*idxp)--;
}

/*
 * Delete the pointer with a specified value from the APlist.
 *
 * entry:
 *	lp - Initialized APlist to delete item from
 *	ptr - Pointer to be deleted.
 *
 * exit:
 *	The list is searched for an item containing the given pointer,
 *	and if a match is found, that item is delted and True (1) returned.
 *	If no match is found, then False (0) is returned.
 *
 * note:
 *	See note for delete operation, above.
 */
int
aplist_delete_value(APlist *lp, const void *ptr)
{
	size_t	idx;

	/*
	 * If the pointer is found in the list, use aplist_delete to
	 * remove it, and we're done.
	 */
	for (idx = 0; idx < lp->apl_nitems; idx++)
		if (ptr == lp->apl_data[idx]) {
			aplist_delete(lp, &idx);
			return (1);
		}

	/* If we get here, the item was not in the list */
	return (0);
}

/*
 * Search the APlist for an element with a given value, and
 * if not found, optionally append the element to the end of the list.
 *
 * entry:
 *	lpp, ptr - As per aplist_insert().
 *	init_arritems - As per aplist_insert() if a non-zero value.
 *		A value of zero is special, and is taken to indicate
 *		that no insert operation should be performed if
 *		the item is not found in the list.
 *
 * exit
 *	The given item is compared to every item in the given APlist.
 *	If it is found, ALE_EXISTS is returned.
 *
 *	If it is not found: If init_arr_items is False (0), then
 *	ALE_NOTFOUND is returned. If init_arr_items is True, then
 *	the item is appended to the list, and ALE_CREATE returned on success.
 *
 *	On failure, which can only occur due to memory allocation failure,
 *	ALE_ALLOCFAIL is returned.
 *
 * note:
 *	The test operation used by this routine is a linear
 *	O(N) operation, and is not efficient for more than a
 *	few items.
 */
aplist_test_t
aplist_test(APlist **lpp, const void *ptr, Aliste init_arritems)
{
	APlist	*lp = *lpp;
	size_t	idx;

	/* Is the pointer already in the list? */
	if (lp != NULL)
		for (idx = 0; idx < lp->apl_nitems; idx++)
			if (ptr == lp->apl_data[idx])
				return (ALE_EXISTS);

	/* Is this a no-insert case? If so, report that the item is not found */
	if (init_arritems == 0)
		return (ALE_NOTFND);

	/* Add it to the end of the list */
	if (aplist_append(lpp, ptr, init_arritems) == NULL)
		return (ALE_ALLOCFAIL);
	return (ALE_CREATE);
}

/*
 * Reset the given list to its empty state. Any memory allocated by the
 * list is preserved, ready for reuse, but the list is set to its
 * empty state, equivalent to having called the delete operation for
 * every item.
 *
 * Note that no cleanup of the discarded items is done. The caller must
 * take care of any necessary cleanup before calling aplist_reset().
 */
void
alist_reset(Alist *lp)
{
	if (lp != NULL) {
		lp->al_nitems = 0;
		lp->al_next = ALIST_OFF_DATA;
	}
}

void
aplist_reset(APlist *lp)
{
	if (lp != NULL)
		lp->apl_nitems = 0;
}
