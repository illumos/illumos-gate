/*
 * drm_linux_list.h -- linux list functions for the BSDs.
 * Created: Mon Apr 7 14:30:16 1999 by anholt@FreeBSD.org
 */
/*
 * -
 * Copyright 2003 Eric Anholt
 * Copyright (c) 2009, Intel Corporation.
 * All Rights Reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice (including the next
 * paragraph) shall be included in all copies or substantial portions of the
 * Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
 * VA LINUX SYSTEMS AND/OR ITS SUPPLIERS BE LIABLE FOR ANY CLAIM, DAMAGES OR
 * OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 *
 * Authors:
 *    Eric Anholt <anholt@FreeBSD.org>
 *
 */

/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _DRM_LINUX_LIST_H_
#define	_DRM_LINUX_LIST_H_

struct list_head {
	struct list_head *next, *prev;
	caddr_t contain_ptr;
};

/* Cheat, assume the list_head is at the start of the struct */
#define	list_entry(entry, type, member)	(type *)(uintptr_t)(entry->contain_ptr)

#define	INIT_LIST_HEAD(head) { \
	(head)->next = head;   \
	(head)->prev = head;   \
	(head)->contain_ptr = (caddr_t)head;	\
}

#define	list_add(entry, head, con_ptr) {	\
	(head)->next->prev = entry;	\
	(entry)->next = (head)->next;	\
	(entry)->prev = head;	\
	(head)->next = entry;	\
	(entry)->contain_ptr = con_ptr;	\
}

#define	list_add_tail(entry, head, con_ptr) {  \
	(entry)->prev = (head)->prev; \
	(entry)->next = head;         \
	(head)->prev->next = entry;   \
	(head)->prev = entry;         \
	(entry)->contain_ptr = con_ptr;	\
}

#define	list_del(entry) {                         \
	(entry)->next->prev = (entry)->prev;      \
	(entry)->prev->next = (entry)->next;      \
	(entry)->contain_ptr = NULL;	\
}

#define	list_for_each(entry, head)				\
    for (entry = (head)->next; entry != head; entry = (entry)->next)

#define	list_for_each_safe(entry, temp, head)			\
    for (entry = (head)->next, temp = (entry)->next;		\
	entry != head; 						\
	entry = temp, temp = temp->next)

#define	list_del_init(entry) {				\
	list_del(entry);				\
	INIT_LIST_HEAD(entry);		\
}

#define	list_move_tail(entry, head, con_ptr) {				\
	list_del(entry);					\
	list_add_tail(entry, head, con_ptr);		\
}

#define	list_empty(head)	((head)->next == head)

#endif /* _DRM_LINUX_LIST_H_ */
