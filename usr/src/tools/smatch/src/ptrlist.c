/*
 * ptrlist.c
 *
 * Pointer list manipulation
 *
 * (C) Copyright Linus Torvalds 2003-2005
 */
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "ptrlist.h"
#include "allocate.h"
#include "compat.h"

__DECLARE_ALLOCATOR(struct ptr_list, ptrlist);
__ALLOCATOR(struct ptr_list, "ptr list", ptrlist);
__ALLOCATOR(struct ptr_list, "rl ptr list", rl_ptrlist);

int ptr_list_size(struct ptr_list *head)
{
	int nr = 0;

	if (head) {
		struct ptr_list *list = head;
		do {
			nr += list->nr - list->rm;
		} while ((list = list->next) != head);
	}
	return nr;
}

/*
 * Linearize the entries of a list up to a total of 'max',
 * and return the nr of entries linearized.
 *
 * The array to linearize into (second argument) should really
 * be "void *x[]", but we want to let people fill in any kind
 * of pointer array, so let's just call it "void **".
 */
int linearize_ptr_list(struct ptr_list *head, void **arr, int max)
{
	int nr = 0;
	if (head && max > 0) {
		struct ptr_list *list = head;

		do {
			int i = list->nr;
			if (i > max) 
				i = max;
			memcpy(arr, list->list, i*sizeof(void *));
			arr += i;
			nr += i;
			max -= i;
			if (!max)
				break;
		} while ((list = list->next) != head);
	}
	return nr;
}

/*
 * When we've walked the list and deleted entries,
 * we may need to re-pack it so that we don't have
 * any empty blocks left (empty blocks upset the
 * walking code
 */
void pack_ptr_list(struct ptr_list **listp)
{
	struct ptr_list *head = *listp;

	if (head) {
		struct ptr_list *entry = head;
		do {
			struct ptr_list *next;
restart:
			next = entry->next;
			if (!entry->nr) {
				struct ptr_list *prev;
				if (next == entry) {
					__free_ptrlist(entry);
					*listp = NULL;
					return;
				}
				prev = entry->prev;
				prev->next = next;
				next->prev = prev;
				__free_ptrlist(entry);
				if (entry == head) {
					*listp = next;
					head = next;
					entry = next;
					goto restart;
				}
			}
			entry = next;
		} while (entry != head);
	}
}		

void split_ptr_list_head(struct ptr_list *head)
{
	int old = head->nr, nr = old / 2;
	struct ptr_list *newlist = __alloc_ptrlist(0);
	struct ptr_list *next = head->next;

	old -= nr;
	head->nr = old;
	newlist->next = next;
	next->prev = newlist;
	newlist->prev = head;
	head->next = newlist;
	newlist->nr = nr;
	memcpy(newlist->list, head->list + old, nr * sizeof(void *));
	memset(head->list + old, 0xf0, nr * sizeof(void *));
}

int rl_ptrlist_hack;
void **__add_ptr_list(struct ptr_list **listp, void *ptr, unsigned long tag)
{
	struct ptr_list *list = *listp;
	struct ptr_list *last = NULL; /* gcc complains needlessly */
	void **ret;
	int nr;

	/* The low two bits are reserved for tags */
	assert((3 & (unsigned long)ptr) == 0);
	assert((~3 & tag) == 0);
	ptr = (void *)(tag | (unsigned long)ptr);

	if (!list || (nr = (last = list->prev)->nr) >= LIST_NODE_NR) {
		struct ptr_list *newlist;

		if (rl_ptrlist_hack)
			newlist = __alloc_rl_ptrlist(0);
		else
			newlist = __alloc_ptrlist(0);
		if (!list) {
			newlist->next = newlist;
			newlist->prev = newlist;
			*listp = newlist;
		} else {
			newlist->prev = last;
			newlist->next = list;
			list->prev = newlist;
			last->next = newlist;
		}
		last = newlist;
		nr = 0;
	}
	ret = last->list + nr;
	*ret = ptr;
	nr++;
	last->nr = nr;
	return ret;
}

int delete_ptr_list_entry(struct ptr_list **list, void *entry, int count)
{
	void *ptr;

	FOR_EACH_PTR(*list, ptr) {
		if (ptr == entry) {
			DELETE_CURRENT_PTR(ptr);
			if (!--count)
				goto out;
		}
	} END_FOR_EACH_PTR(ptr);
	assert(count <= 0);
out:
	pack_ptr_list(list);
	return count;
}

int replace_ptr_list_entry(struct ptr_list **list, void *old_ptr, void *new_ptr, int count)
{
	void *ptr;

	FOR_EACH_PTR(*list, ptr) {
		if (ptr==old_ptr) {
			REPLACE_CURRENT_PTR(ptr, new_ptr);
			if (!--count)
				goto out;
		}
	}END_FOR_EACH_PTR(ptr);
	assert(count <= 0);
out:
	return count;
}

/* This removes the last entry, but doesn't pack the ptr list */
void * undo_ptr_list_last(struct ptr_list **head)
{
	struct ptr_list *last, *first = *head;

	if (!first)
		return NULL;
	last = first;
	do {
		last = last->prev;
		if (last->nr) {
			void *ptr;
			int nr = --last->nr;
			ptr = last->list[nr];
			last->list[nr] = (void *)0xf1f1f1f1;
			return ptr;
		}
	} while (last != first);
	return NULL;
}

void * delete_ptr_list_last(struct ptr_list **head)
{
	void *ptr = NULL;
	struct ptr_list *last, *first = *head;

	if (!first)
		return NULL;
	last = first->prev;
	if (last->nr)
		ptr = last->list[--last->nr];
	if (last->nr <=0) {
		first->prev = last->prev;
		last->prev->next = first;
		if (last == first)
			*head = NULL;
		__free_ptrlist(last);
	}
	return ptr;
}

void concat_ptr_list(struct ptr_list *a, struct ptr_list **b)
{
	void *entry;
	FOR_EACH_PTR(a, entry) {
		add_ptr_list(b, entry);
	} END_FOR_EACH_PTR(entry);
}

void __free_ptr_list(struct ptr_list **listp)
{
	struct ptr_list *tmp, *list = *listp;

	if (!list)
		return;

	list->prev->next = NULL;
	while (list) {
		tmp = list;
		list = list->next;
		__free_ptrlist(tmp);
	}

	*listp = NULL;
}
