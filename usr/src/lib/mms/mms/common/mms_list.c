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
 *
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */


#include <mms_list.h>

/*
 * Initialize a list like another one.
 */
void
mms_list_create_like(mms_list_t *targ, mms_list_t *src)
{
	mms_list_create(targ, src->list_size, src->list_offset);
}

/*
 * Move a list to an uninitialized list and make the original list empty.
 */
void
mms_list_move(mms_list_t *targ, mms_list_t *src)
{
	mms_list_create_like(targ, src);
	mms_list_move_tail(targ, src);
}

void
mms_list_insert_after_node(mms_list_t *list,
    mms_list_node_t *node, void *object)
{
	mms_list_node_t *lnew = mms_list_d2l(list, object);
	assert(MMS_LIST_NOT_MOVED(list));
	lnew->list_prev = node;
	lnew->list_next = node->list_next;
	node->list_next->list_prev = lnew;
	node->list_next = lnew;
}

void
mms_list_insert_before_node(mms_list_t *list,
    mms_list_node_t *node, void *object)
{
	mms_list_node_t *lnew = mms_list_d2l(list, object);
	assert(MMS_LIST_NOT_MOVED(list));
	lnew->list_next = node;
	lnew->list_prev = node->list_prev;
	node->list_prev->list_next = lnew;
	node->list_prev = lnew;
}


void
mms_list_create(mms_list_t *list, size_t size, size_t offset)
{
	assert(list);
	assert(size > 0);
	assert(size >= offset + sizeof (mms_list_node_t));

	list->list_size = size;
	list->list_offset = offset;
	list->list_head.list_next = list->list_head.list_prev =
	    &list->list_head;
}

void
mms_list_destroy(mms_list_t *list)
{
	mms_list_node_t *node = &list->list_head;

	assert(list);
	assert(list->list_head.list_next == node);
	assert(list->list_head.list_prev == node);

	assert(MMS_LIST_NOT_MOVED(list));
	node->list_next = node->list_prev = NULL;
}

void
mms_list_insert_after(mms_list_t *list, void *object, void *nobject)
{
	mms_list_node_t *lold = mms_list_d2l(list, object);
	mms_list_insert_after_node(list, lold, nobject);
}

void
mms_list_insert_before(mms_list_t *list, void *object, void *nobject)
{
	mms_list_node_t *lold = mms_list_d2l(list, object);
	mms_list_insert_before_node(list, lold, nobject);
}

void
mms_list_insert_head(mms_list_t *list, void *object)
{
	mms_list_node_t *lold = &list->list_head;
	mms_list_insert_after_node(list, lold, object);
}

void
mms_list_insert_tail(mms_list_t *list, void *object)
{
	mms_list_node_t *lold = &list->list_head;
	mms_list_insert_before_node(list, lold, object);
}

void
mms_list_remove(mms_list_t *list, void *object)
{
	mms_list_node_t *lold = mms_list_d2l(list, object);

	assert(!mms_list_empty(list));
	assert(MMS_LIST_NOT_MOVED(list));
	lold->list_prev->list_next = lold->list_next;
	lold->list_next->list_prev = lold->list_prev;
	lold->list_next = lold->list_prev = NULL;
}

void *
mms_list_head(mms_list_t *list)
{
	assert(MMS_LIST_NOT_MOVED(list));
	if (mms_list_empty(list))
		return (NULL);
	return (mms_list_object(list, list->list_head.list_next));
}

void *
mms_list_tail(mms_list_t *list)
{
	assert(MMS_LIST_NOT_MOVED(list));
	if (mms_list_empty(list))
		return (NULL);
	return (mms_list_object(list, list->list_head.list_prev));
}

void *
mms_list_next(mms_list_t *list, void *object)
{
	mms_list_node_t *node = mms_list_d2l(list, object);

	assert(MMS_LIST_NOT_MOVED(list));
	if (node->list_next != &list->list_head)
		return (mms_list_object(list, node->list_next));

	return (NULL);
}

void *
mms_list_prev(mms_list_t *list, void *object)
{
	mms_list_node_t *node = mms_list_d2l(list, object);

	assert(MMS_LIST_NOT_MOVED(list));
	if (node->list_prev != &list->list_head)
		return (mms_list_object(list, node->list_prev));

	return (NULL);
}

/*
 *  Insert src list after dst list. Empty src list thereafter.
 */
void
mms_list_move_tail(mms_list_t *dst, mms_list_t *src)
{
	mms_list_node_t *dstnode = &dst->list_head;
	mms_list_node_t *srcnode = &src->list_head;

	assert(dst->list_size == src->list_size);
	assert(dst->list_offset == src->list_offset);

	assert(MMS_LIST_NOT_MOVED(src));
	assert(MMS_LIST_NOT_MOVED(dst));
	if (mms_list_empty(src))
		return;

	dstnode->list_prev->list_next = srcnode->list_next;
	srcnode->list_next->list_prev = dstnode->list_prev;
	dstnode->list_prev = srcnode->list_prev;
	srcnode->list_prev->list_next = dstnode;

	/* empty src list */
	srcnode->list_next = srcnode->list_prev = srcnode;
}
