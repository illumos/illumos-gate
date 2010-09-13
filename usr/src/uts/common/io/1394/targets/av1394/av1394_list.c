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
 * Copyright 2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Yet another list implementation
 *    This is a multipurpose double-linked list. It requires that the first
 *    two structure members of each item are the 'next' and 'prev' pointers.
 *    This works for mblk's and other data types utilized by av1394.
 *
 *    Locking is provided by the caller.
 */

#include <sys/1394/targets/av1394/av1394_impl.h>

#define	ITEM(i)	((av1394_list_item_t *)(i))

/*
 * av1394_list_init()
 *    Initializes the list
 */
void
av1394_list_init(av1394_list_t *lp)
{
	lp->l_head = lp->l_tail = NULL;
	lp->l_cnt = 0;
}

/*
 * av1394_list_head()
 *    Returns pointer to the first item in the list (but does not remove it)
 */
void *
av1394_list_head(av1394_list_t *lp)
{
	return (lp->l_head);
}


/*
 * av1394_list_put_tail()
 *    Adds item to the end of the list
 */
void
av1394_list_put_tail(av1394_list_t *lp, void *item)
{
	ITEM(item)->i_next = NULL;
	ITEM(item)->i_prev = lp->l_tail;
	if (lp->l_tail == NULL) {
		ASSERT(lp->l_head == 0);
		ASSERT(lp->l_cnt == 0);
		lp->l_head = lp->l_tail = item;
	} else {
		lp->l_tail->i_next = item;
		lp->l_tail = item;
	}
	lp->l_cnt++;
}

/*
 * av1394_list_put_head()
 *    Inserts item in the front of the list
 */
void
av1394_list_put_head(av1394_list_t *lp, void *item)
{
	ITEM(item)->i_next = lp->l_head;
	ITEM(item)->i_prev = NULL;
	if (lp->l_head == NULL) {
		ASSERT(lp->l_tail == 0);
		ASSERT(lp->l_cnt == 0);
		lp->l_head = lp->l_tail = item;
	} else {
		lp->l_head->i_prev = item;
		lp->l_head = item;
	}
	lp->l_cnt++;
}

/*
 * av1394_list_get_head()
 *    Removes and returns an item from the front of the list
 */
void *
av1394_list_get_head(av1394_list_t *lp)
{
	av1394_list_item_t	*item;

	item = lp->l_head;
	if (item != NULL) {
		lp->l_head = item->i_next;
		if (item == lp->l_tail) {
			ASSERT(lp->l_cnt == 1);
			ASSERT(lp->l_head == NULL);
			lp->l_tail = NULL;
			lp->l_cnt = 0;
		} else {
			ASSERT(lp->l_cnt > 1);
			item->i_next->i_prev = item->i_prev;
			lp->l_cnt--;
		}
		item->i_next = item->i_prev = NULL;
	}
	return (item);
}
