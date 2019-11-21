/*
 * ptrlist.c
 *
 * (C) Copyright Linus Torvalds 2003-2005
 */

///
// Pointer list manipulation
// -------------------------

#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "ptrlist.h"
#include "allocate.h"
#include "compat.h"

__DECLARE_ALLOCATOR(struct ptr_list, ptrlist);
__ALLOCATOR(struct ptr_list, "ptr list", ptrlist);
__ALLOCATOR(struct ptr_list, "rl ptr list", rl_ptrlist);

///
// get the size of a ptrlist
// @head: the head of the list
// @return: the size of the list given by @head.
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

///
// test if a list is empty
// @head: the head of the list
// @return: ``true`` if the list is empty, ``false`` otherwise.
bool ptr_list_empty(const struct ptr_list *head)
{
	const struct ptr_list *list = head;

	if (!head)
		return true;

	do {
		if (list->nr - list->rm)
			return false;
	} while ((list = list->next) != head);

	return true;
}

///
// test is a list contains more than one element
// @head: the head of the list
// @return: ``true`` if the list has more than 1 element, ``false`` otherwise.
bool ptr_list_multiple(const struct ptr_list *head)
{
	const struct ptr_list *list = head;
	int nr = 0;

	if (!head)
		return false;

	do {
		nr += list->nr - list->rm;
		if (nr > 1)
			return true;
	} while ((list = list->next) != head);

	return false;
}

///
// get the first element of a ptrlist
// @head: the head of the list
// @return: the first element of the list or ``NULL`` if the list is empty
void *first_ptr_list(struct ptr_list *head)
{
	struct ptr_list *list = head;

	if (!head)
		return NULL;

	while (list->nr == 0) {
		list = list->next;
		if (list == head)
			return NULL;
	}
	return PTR_ENTRY_NOTAG(list, 0);
}

///
// get the last element of a ptrlist
// @head: the head of the list
// @return: the last element of the list or ``NULL`` if the list is empty
void *last_ptr_list(struct ptr_list *head)
{
	struct ptr_list *list;

	if (!head)
		return NULL;
	list = head->prev;
	while (list->nr == 0) {
		if (list == head)
			return NULL;
		list = list->prev;
	}
	return PTR_ENTRY_NOTAG(list, list->nr-1);
}

///
// get the nth element of a ptrlist
// @head: the head of the list
// @return: the nth element of the list or ``NULL`` if the list is too short.
void *ptr_list_nth_entry(struct ptr_list *list, unsigned int idx)
{
	struct ptr_list *head = list;

	if (!head)
		return NULL;

	do {
		unsigned int nr = list->nr;

		if (idx < nr)
			return list->list[idx];
		else
			idx -= nr;
	} while ((list = list->next) != head);
	return NULL;
}

///
// linearize the entries of a list
//
// @head: the list to be linearized
// @arr: a ``void*`` array to fill with @head's entries
// @max: the maximum number of entries to store into @arr
// @return: the number of entries linearized.
//
// Linearize the entries of a list up to a total of @max,
// and return the nr of entries linearized.
//
// The array to linearize into (@arr) should really
// be ``void *x[]``, but we want to let people fill in any kind
// of pointer array, so let's just call it ``void **``.
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

///
// pack a ptrlist
//
// @listp: a pointer to the list to be packed.
//
// When we've walked the list and deleted entries,
// we may need to re-pack it so that we don't have
// any empty blocks left (empty blocks upset the
// walking code).
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

///
// split a ptrlist block
// @head: the ptrlist block to be splitted
//
// A new block is inserted just after @head and the entries
// at the half end of @head are moved to this new block.
// The goal being to create space inside @head for a new entry.
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
///
// add an entry to a ptrlist
// @listp: a pointer to the list
// @ptr: the entry to add to the list
// @return: the address where the new entry is stored.
//
// :note: code must not use this function and should use
//	:func:`add_ptr_list` instead.
void **__add_ptr_list(struct ptr_list **listp, void *ptr)
{
	struct ptr_list *list = *listp;
	struct ptr_list *last = NULL; /* gcc complains needlessly */
	void **ret;
	int nr;

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

///
// add a tagged entry to a ptrlist
// @listp: a pointer to the list
// @ptr: the entry to add to the list
// @tag: the tag to add to @ptr
// @return: the address where the new entry is stored.
//
// :note: code must not use this function and should use
//	:func:`add_ptr_list_tag` instead.
void **__add_ptr_list_tag(struct ptr_list **listp, void *ptr, unsigned long tag)
{
	/* The low two bits are reserved for tags */
	assert((3 & (unsigned long)ptr) == 0);
	assert((~3 & tag) == 0);

	ptr = (void *)(tag | (unsigned long)ptr);

	return __add_ptr_list(listp, ptr);
}

///
// test if some entry is already present in a ptrlist
// @list: the head of the list
// @entry: the entry to test
// @return: ``true`` if the entry is already present, ``false`` otherwise.
bool lookup_ptr_list_entry(const struct ptr_list *head, const void *entry)
{
	const struct ptr_list *list = head;

	if (!head)
		return false;
	do {
		int nr = list->nr;
		int i;
		for (i = 0; i < nr; i++)
			if (list->list[i] == entry)
				return true;
	} while ((list = list->next) != head);
	return false;
}

///
// delete an entry from a ptrlist
// @list: a pointer to the list
// @entry: the item to be deleted
// @count: the minimum number of times @entry should be deleted or 0.
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

///
// replace an entry in a ptrlist
// @list: a pointer to the list
// @old_ptr: the entry to be replaced
// @new_ptr: the new entry
// @count: the minimum number of times @entry should be deleted or 0.
int replace_ptr_list_entry(struct ptr_list **list, void *old_ptr,
	void *new_ptr, int count)
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

///
// remove the last entry of a ptrlist
// @head: a pointer to the list
// @return: the last elemant of the list or NULL if the list is empty.
//
// :note: this doesn't repack the list
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

///
// remove the last entry and repack the list
// @head: a pointer to the list
// @return: the last elemant of the list or NULL if the list is empty.
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

///
// concat two ptrlists
// @a: the source list
// @b: a pointer to the destination list.
// The element of @a are added at the end of @b.
void concat_ptr_list(struct ptr_list *a, struct ptr_list **b)
{
	void *entry;
	FOR_EACH_PTR(a, entry) {
		add_ptr_list(b, entry);
	} END_FOR_EACH_PTR(entry);
}

///
// copy the elements of a list at the end of another list.
// @listp: a pointer to the destination list.
// @src: the head of the source list.
void copy_ptr_list(struct ptr_list **listp, struct ptr_list *src)
{
	struct ptr_list *head, *tail;
	struct ptr_list *cur = src;
	int idx;

	if (!src)
		return;
	head = *listp;
	if (!head) {
		*listp = src;
		return;
	}

	tail = head->prev;
	idx = tail->nr;
	do {
		struct ptr_list *next;
		int nr = cur->nr;
		int i;
		for (i = 0; i < nr;) {
			void *ptr = cur->list[i++];
			if (!ptr)
				continue;
			if (idx >= LIST_NODE_NR) {
				struct ptr_list *prev = tail;
				tail = __alloc_ptrlist(0);
				prev->next = tail;
				tail->prev = prev;
				prev->nr = idx;
				idx = 0;
			}
			tail->list[idx++] = ptr;
		}

		next = cur->next;
		__free_ptrlist(cur);
		cur = next;
	} while (cur != src);

	tail->nr = idx;
	head->prev = tail;
	tail->next = head;
}

///
// free a ptrlist
// @listp: a pointer to the list
// Each blocks of the list are freed (but the entries
// themselves are not freed).
//
// :note: code must not use this function and should use
//	the macro :func:`free_ptr_list` instead.
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
