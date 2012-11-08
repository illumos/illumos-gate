/*
 * mr_sas_list.h: header for mr_sas
 *
 * Solaris MegaRAID driver for SAS2.0 controllers
 * Copyright (c) 2008-2012, LSI Logic Corporation.
 * All rights reserved.
 */

/* Copyright 2012 Nexenta Systems, Inc. All rights reserved. */

/*
 * Extract C functions from LSI-provided mr_sas_list.h such that we can both
 * be lint-clean and provide a slightly better source organizational model
 * beyond preprocessor abuse.
 */

#include "mr_sas_list.h"

/*
 * Insert a new entry between two known consecutive entries.
 *
 * This is only for internal list manipulation where we know
 * the prev/next entries already!
 */
static inline void
__list_add(struct mlist_head *new, struct mlist_head *prev,
    struct mlist_head *next)
{
	next->prev = new;
	new->next = next;
	new->prev = prev;
	prev->next = new;
}

/*
 * mlist_add - add a new entry
 * @new: new entry to be added
 * @head: list head to add it after
 *
 * Insert a new entry after the specified head.
 * This is good for implementing stacks.
 */
void
mlist_add(struct mlist_head *new, struct mlist_head *head)
{
	__list_add(new, head, head->next);
}

/*
 * mlist_add_tail - add a new entry
 * @new: new entry to be added
 * @head: list head to add it before
 *
 * Insert a new entry before the specified head.
 * This is useful for implementing queues.
 */
void
mlist_add_tail(struct mlist_head *new, struct mlist_head *head)
{
	__list_add(new, head->prev, head);
}

/*
 * Delete a list entry by making the prev/next entries
 * point to each other.
 *
 * This is only for internal list manipulation where we know
 * the prev/next entries already!
 */
static inline void
__list_del(struct mlist_head *prev, struct mlist_head *next)
{
	next->prev = prev;
	prev->next = next;
}

/*
 * mlist_del_init - deletes entry from list and reinitialize it.
 * @entry: the element to delete from the list.
 */
void
mlist_del_init(struct mlist_head *entry)
{
	__list_del(entry->prev, entry->next);
	INIT_LIST_HEAD(entry);
}

/*
 * mlist_empty - tests whether a list is empty
 * @head: the list to test.
 */
int
mlist_empty(struct mlist_head *head)
{
	return (head->next == head);
}

/*
 * mlist_splice - join two lists
 * @list: the new list to add.
 * @head: the place to add it in the first list.
 */
void
mlist_splice(struct mlist_head *list, struct mlist_head *head)
{
	struct mlist_head *first = list->next;

	if (first != list) {
		struct mlist_head *last = list->prev;
		struct mlist_head *at = head->next;

		first->prev = head;
		head->next = first;

		last->next = at;
		at->prev = last;
	}
}
