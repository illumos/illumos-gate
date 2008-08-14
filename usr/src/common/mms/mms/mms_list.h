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




#ifndef	_MMS_LIST_H_
#define	_MMS_LIST_H_

#include <sys/types.h>
#include <assert.h>
#include <sys/list_impl.h>
#include <sys/list.h>
#include <stddef.h>

typedef	struct mms_list_node {
	struct mms_list_node *list_next;
	struct mms_list_node *list_prev;
}	mms_list_node_t;

typedef	struct mms_list {
	size_t	list_size;
	size_t	list_offset;
	struct mms_list_node list_head;
}	mms_list_t;

/*
 * Generic doubly-linked list implementation
 */
#define	MMS_LIST_NOT_MOVED(list) \
	((mms_list_t *)((ptrdiff_t)((list)->list_head.list_next->list_prev) - \
	    offsetof(mms_list_t, list_head)) == (list))

#define	mms_list_d2l(a, obj) \
	((mms_list_node_t *)((ptrdiff_t)((intptr_t)obj) + (a)->list_offset))
#define	mms_list_object(a, node) \
	((void *)((ptrdiff_t)((intptr_t)node) - (a)->list_offset))
#define	mms_list_empty(a) ((a)->list_head.list_next == &(a)->list_head)

/*
 * Define and initailze a list
 */
#define	MMS_LIST_CREATE(list, structname, link)				\
	mms_list_t list = {						\
		sizeof (structname),					\
		offsetof(structname, link),				\
		&list.list_head,					\
		&list.list_head						\
	}

/*
 * Some useful macros
 */
#define	mms_list_foreach(list, obj)					\
	for (obj = mms_list_head(list); obj != NULL;			\
	    obj = mms_list_next(list, obj))

/*
 * Get name value string pairs.
 */
#define	mms_list_pair_foreach(list, name, value)			\
	for (name = mms_list_head(list), 				\
	    value = (name != NULL ? mms_list_next(list, name) : NULL);	\
	    name != NULL && value != NULL; 				\
	    name = mms_list_next(list, value),				\
	    value = (name != NULL ? mms_list_next(list, name) : NULL))


/*
 * Safe to remove the current object from the list.
 */
#define	mms_list_foreach_safe(list, obj, next)				\
	for (obj = mms_list_head(list);					\
	    ((next = obj != NULL ? mms_list_next(list, obj) : NULL),    \
	    obj != NULL); obj = next)

void mms_list_create(mms_list_t *, size_t, size_t);
void mms_list_destroy(mms_list_t *);

void mms_list_insert_after(mms_list_t *, void *, void *);
void mms_list_insert_before(mms_list_t *, void *, void *);
void mms_list_insert_head(mms_list_t *, void *);
void mms_list_insert_tail(mms_list_t *, void *);
void mms_list_remove(mms_list_t *, void *);
void mms_list_move_tail(mms_list_t *, mms_list_t *);

void *mms_list_head(mms_list_t *);
void *mms_list_tail(mms_list_t *);
void *mms_list_next(mms_list_t *, void *);
void *mms_list_prev(mms_list_t *, void *);
void mms_list_create_like(mms_list_t *targ, mms_list_t *src);
void mms_list_move(mms_list_t *targ, mms_list_t *src);

#endif	/* _MMS_LIST_H_ */
