/*
 * drm_linux_list.h -- linux list functions for the BSDs.
 * Created: Mon Apr 7 14:30:16 1999 by anholt@FreeBSD.org
 */
/*
 * -
 * Copyright 2003 Eric Anholt
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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifndef _DRM_LINUX_LIST_H_
#define	_DRM_LINUX_LIST_H_

struct list_head {
	struct list_head *next, *prev;
};

/* Cheat, assume the list_head is at the start of the struct */
#define	list_entry(entry, type, member)	(type *)(entry)

#define	INIT_LIST_HEAD(head) { \
	(head)->next = head;   \
	(head)->prev = head;   \
}

#define	list_add_tail(entry, head) {  \
	(entry)->prev = (head)->prev; \
	(entry)->next = head;         \
	(head)->prev->next = entry;   \
	(head)->prev = entry;         \
}

#define	list_del(entry) {                         \
	(entry)->next->prev = (entry)->prev;      \
	(entry)->prev->next = (entry)->next;      \
}

#define	list_for_each(entry, head)				\
    for (entry = (head)->next; entry != head; entry = (entry)->next)

#define	list_for_each_safe(entry, temp, head)			\
    for (entry = (head)->next, temp = (entry)->next;		\
	temp != head; 						\
	entry = temp, temp = temp->next)

#endif /* _DRM_LINUX_LIST_H_ */
