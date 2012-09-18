/*
 * mr_sas_list.h: header for mr_sas
 *
 * Solaris MegaRAID driver for SAS2.0 controllers
 * Copyright (c) 2008-2012, LSI Logic Corporation.
 * All rights reserved.
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
#if 0
void mlist_del(struct mlist_head *);
#endif
void mlist_del_init(struct mlist_head *);
int mlist_empty(struct mlist_head *);
void mlist_splice(struct mlist_head *, struct mlist_head *);

/* TODO: set this */
#if 0
#pragma	inline(list_add, list_add_tail, __list_del, list_del,
		list_del_init, list_empty, list_splice)
#endif


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
