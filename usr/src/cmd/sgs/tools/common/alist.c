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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sgs.h>
#include <string.h>
#include <stdlib.h>

/*
 * Alist manipulation.  An Alist is a list of elements formed into an array.
 * Traversal of the list is an array scan, which because of the locality of
 * each reference is probably more efficient than a link-list traversal.
 *
 * The elements of an Alist are variable length.  They can be pointers to
 * other data structures, or data structures themselves.  Traversal of an Alist
 * thus returns a pointer to each data element.
 *
 * Alist elements can be deleted.  This involve sliding any following elements
 * over the element being deleted.  ALIST_TRAVERSE() may be employed to traverse
 * the list, at the same time elements are being deleted.  Therefore, the next
 * element is always determined as an offset from the beginning of the list.
 */
void *
alist_append(Alist ** alpp, const void * item, size_t size, int cnt)
{
	Alist *	alp = *alpp;
	void *	new;

	if (alp == 0) {
		Aliste	bsize, esize = (Aliste)S_ROUND(size, sizeof (void *));

		/*
		 * First time here, allocate a new Alist.  Note that the Alist
		 * al_desc[] entry accounts for one void * already.
		 */
		bsize = (Aliste)(sizeof (Alist) - sizeof (void *) +
		    (size * cnt));
		if ((alp = malloc((size_t)bsize)) == 0)
			return (0);
		alp->al_next = sizeof (Alist) - sizeof (void *);
		alp->al_end = bsize;
		alp->al_size = esize;

	} else if (alp->al_next == alp->al_end) {
		Aliste	bsize;

		/*
		 * The list is full, add another block of elements.  Determine
		 * the present number of elements and double them.
		 */
		bsize = (Aliste)((alp->al_end * 2) - sizeof (Alist) +
		    sizeof (void *));
		if ((alp = realloc((void *)alp, (size_t)bsize)) == 0)
			return (0);
		alp->al_end = bsize;
	}

	new = (void *)((char *)alp + alp->al_next);
	alp->al_next += alp->al_size;

	/*
	 * If a data item has been provided, initialize the current alist entry
	 * with this item.  Otherwise, initialize the entry to zero, presumably
	 * the caller will fill this in.
	 */
	if (item)
		(void) memcpy(new, item, alp->al_size);
	else
		(void) memset(new, 0, alp->al_size);

	*alpp = alp;
	return (new);
}

/*
 * Delete an element from an Alist.  If a count is provided then the caller
 * already knows what element to remove.  Return a decremented count value so
 * that the caller can continue an ALIST_TRAVERSE scan.
 */
int
alist_delete(Alist *alp, const void *item, Aliste *offp)
{
	void	*addr;
	Aliste	off;

	if (offp) {
		off = *offp;
		addr = (void *)((char *)alp + off);
	} else {
		for (ALIST_TRAVERSE(alp, off, addr)) {
			if (memcmp(addr, item, alp->al_size) == 0)
				break;
		}
	}

	if (off >= alp->al_next)
		return (0);

	/*
	 * If the element to be removed is not the last entry of the array,
	 * slide the following elements over the present element.
	 */
	if (off < (alp->al_next -= alp->al_size)) {
		(void) memmove((void *)addr, (void *)((char *)addr +
		    alp->al_size), (alp->al_next - off));
	}

	/*
	 * Reset the new offset, and decrement the callers count control
	 * variable if necessary.  Null out the old tail element.
	 */
	addr = (void *)((char *)alp + alp->al_next);
	(void) memset(addr, 0, alp->al_size);

	if (offp)
		*offp -= alp->al_size;

	return (1);
}

/*
 * Generic alist test and append routine.
 */
int
alist_test(Alist ** alpp, void * ip, size_t size, int cnt)
{
	Aliste	off;
	void **	ipp;

	for (ALIST_TRAVERSE(*alpp, off, ipp)) {
		if (size == sizeof (uintptr_t)) {
			if (ip == *ipp)
				return (ALE_EXISTS);
		} else {
			if (memcmp(ip, *ipp, size) == 0)
				return (ALE_EXISTS);
		}
	}

	if (cnt) {
		if (alist_append(alpp, &ip, size, cnt) == 0)
			return (0);
	}
	return (ALE_CREATE);
}
