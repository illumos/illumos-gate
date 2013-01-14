/*
 * mr_sas_list.h: header for mr_sas
 *
 * Solaris MegaRAID driver for SAS2.0 controllers
 * Copyright (c) 2008-2012, LSI Logic Corporation.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the author nor the names of its contributors may be
 *    used to endorse or promote products derived from this software without
 *    specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 */

#ifndef	_MR_SAS_LIST_H_
#define	_MR_SAS_LIST_H_

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Simple doubly linked list implementation.
 *
 * Some of the internal functions ("__xxx") are useful when
 * manipulating whole lists rather than single entries, as
 * sometimes we already know the next/prev entries and we can
 * generate better code by using them directly rather than
 * using the generic single-entry routines.
 */

struct mlist_head {
	struct mlist_head *next, *prev;
};

typedef struct mlist_head mlist_t;

#define	LIST_HEAD_INIT(name) { &(name), &(name) }

#define	LIST_HEAD(name) \
	struct mlist_head name = LIST_HEAD_INIT(name)

#define	INIT_LIST_HEAD(ptr) { \
	(ptr)->next = (ptr); (ptr)->prev = (ptr); \
}


void mlist_add(struct mlist_head *, struct mlist_head *);
void mlist_add_tail(struct mlist_head *, struct mlist_head *);
void mlist_del_init(struct mlist_head *);
int mlist_empty(struct mlist_head *);
void mlist_splice(struct mlist_head *, struct mlist_head *);

/*
 * mlist_entry - get the struct for this entry
 * @ptr:	the &struct mlist_head pointer.
 * @type:	the type of the struct this is embedded in.
 * @member:	the name of the list_struct within the struct.
 */
#define	mlist_entry(ptr, type, member) \
	((type *)((size_t)(ptr) - offsetof(type, member)))


/*
 * mlist_for_each	-	iterate over a list
 * @pos:	the &struct mlist_head to use as a loop counter.
 * @head:	the head for your list.
 */
#define	mlist_for_each(pos, head) \
	for (pos = (head)->next, prefetch(pos->next); pos != (head); \
		pos = pos->next, prefetch(pos->next))


/*
 * mlist_for_each_safe - iterate over a list safe against removal of list entry
 * @pos:	the &struct mlist_head to use as a loop counter.
 * @n:		another &struct mlist_head to use as temporary storage
 * @head:	the head for your list.
 */
#define	mlist_for_each_safe(pos, n, head) \
	for (pos = (head)->next, n = pos->next; pos != (head); \
		pos = n, n = pos->next)

#ifdef __cplusplus
}
#endif

#endif /* _MR_SAS_LIST_H_ */
