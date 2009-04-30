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
 */

/*
 * Copyright (c) 2002-2003, Network Appliance, Inc. All rights reserved.
 */

/*
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 *
 * MODULE: dapl_llist.c
 *
 * PURPOSE: Manage doubly linked lists within the DAPL Reference Implementation
 *
 *	A link list head points to the first member of a linked list, but
 *	is itself not a member of the list.
 *
 *          +---------------------------------------------+
 *          |      entry         entry         entry      |
 *  HEAD -> |    +-------+     +-------+     +-------+    |
 *          +--> | flink | --> | flink | --> | flink | >--+
 *	         | data  |     | data  |     | data  |
 *	    +--< | blink | <-- | blink | <-- | blink | <--|
 *          |    +-------+     +-------+     +-------+    |
 *          |                                             |
 *          +---------------------------------------------+
 *
 * Note:  Each of the remove functions takes an assertion failure if
 *        an element cannot be removed from the list.
 *
 * $Id: dapl_llist.c,v 1.9 2003/06/13 12:21:11 sjs2 Exp $
 */

#include "dapl.h"

/*
 * dapl_llist_init_head()
 *
 * Purpose: initialize a linked list head
 */
void
dapl_llist_init_head(DAPL_LLIST_HEAD *head)
{
	*head = NULL;
}

/*
 * dapl_llist_init_entry()
 *
 * Purpose: initialize a linked list entry
 */
void
dapl_llist_init_entry(DAPL_LLIST_ENTRY *entry)
{
	entry->blink = NULL;
	entry->flink = NULL;
	entry->data = 0;
	entry->list_head = NULL;
}

/*
 * dapl_llist_is_empty()
 *
 * Purpose: returns TRUE if the linked list is empty
 */
DAT_BOOLEAN
dapl_llist_is_empty(DAPL_LLIST_HEAD *head)
{
	return (*head == NULL);
}

/*
 * dapl_llist_add_head()
 *
 * Purpose: Add an entry to the head of a linked list
 */
void
dapl_llist_add_head(DAPL_LLIST_HEAD *head,
		DAPL_LLIST_ENTRY *entry,
		void *data)
{
	DAPL_LLIST_ENTRY *first;

	/* deal with empty list */
	if (dapl_llist_is_empty(head)) {
		entry->flink = entry;
		entry->blink = entry;
	} else {
		first = *head;
		entry->flink = first;
		entry->blink = first->blink;
		first->blink->flink = entry;
		first->blink = entry;
	}

	*head		= entry;
	entry->data	= data;
	entry->list_head = head;
}

/*
 * dapl_llist_add_tail()
 *
 * Purpose: Add an entry to the tail of a linked list
 */
void
dapl_llist_add_tail(DAPL_LLIST_HEAD *head,
	DAPL_LLIST_ENTRY *entry,
	void *data)
{
	DAPL_LLIST_ENTRY *last;

	/* deal with empty list */
	if (dapl_llist_is_empty(head)) {
		*head = entry;
		entry->flink = entry;
		entry->blink = entry;
	} else {
		last = (*head)->blink;
		entry->flink = last->flink;
		entry->blink = last;
		last->flink->blink = entry;
		last->flink = entry;
	}
	entry->data = data;
	entry->list_head = head;
}


/*
 * dapl_llist_add_entry()
 *
 * Purpose: Add an entry before an element in the list
 */
void
dapl_llist_add_entry(DAPL_LLIST_HEAD * head,
		DAPL_LLIST_ENTRY * entry,
		DAPL_LLIST_ENTRY * new_entry,
		void * data)
{
	DAPL_LLIST_ENTRY *last;

	/* deal with empty list */
	if (dapl_llist_is_empty(head)) {
		*head = entry;
		entry->flink = entry;
		entry->blink = entry;
	} else {
		last = entry->blink;
		entry->blink = new_entry;
		last->flink  = new_entry;

		new_entry->flink = entry;
		new_entry->blink = last;

	}
	new_entry->data = data;
	new_entry->list_head = head;
}

/*
 * dapl_llist_remove_head()
 *
 * Purpose: Remove the first entry of a linked list
 */
void *
dapl_llist_remove_head(DAPL_LLIST_HEAD *head)
{
	DAPL_LLIST_ENTRY *first;

	dapl_os_assert(!dapl_llist_is_empty(head));
	first = *head;
	*head = first->flink;

	first->flink->blink = first->blink;
	first->blink->flink = first->flink;

	if (first->flink == first) {
		*head = NULL;
	}
	/* clean up the links for good measure */
	first->flink = NULL;
	first->blink = NULL;
	first->list_head = NULL;
	return (first->data);
}

/*
 * dapl_llist_remove_tail()
 *
 * Purpose: Remove the last entry of a linked list
 */
void *
dapl_llist_remove_tail(DAPL_LLIST_HEAD *head)
{
	DAPL_LLIST_ENTRY *last;

	dapl_os_assert(!dapl_llist_is_empty(head));
	last = (*head)->blink;

	last->blink->flink = last->flink;
	last->flink->blink = last->blink;

	if (last->flink == last) {
		*head = NULL;
	}
	/* clean up the links for good measure */
	last->flink = NULL;
	last->blink = NULL;
	last->list_head = NULL;

	return (last->data);
}

/*
 * dapl_llist_remove_entry()
 *
 * Purpose: Remove the specified entry from a linked list
 */
void *
dapl_llist_remove_entry(DAPL_LLIST_HEAD *head, DAPL_LLIST_ENTRY *entry)
{
	DAPL_LLIST_ENTRY *first;

	dapl_os_assert(!dapl_llist_is_empty(head));
	first = *head;

	/* if it's the first entry, pull it off */
	if (first == entry) {
		(*head) = first->flink;
		/* if it was the only entry, kill the list */
		if (first->flink == first) {
			(*head) = NULL;
		}
	}
#ifdef VERIFY_LINKED_LIST
	else {
		DAPL_LLIST_ENTRY *try_entry;

		try_entry = first->flink;
		for (;;) {
			if (try_entry == first) {
				/*
				 * not finding the element on the list
				 * is a BAD thing
				 */
				dapl_os_assert(0);
				break;
			}
			if (try_entry == entry) {
				break;
			}
			try_entry = try_entry->flink;
		}
	}
#endif /* VERIFY_LINKED_LIST */

	dapl_os_assert(entry->list_head == head);
	entry->list_head = NULL;

	entry->flink->blink = entry->blink;
	entry->blink->flink = entry->flink;
	entry->flink = NULL;
	entry->blink = NULL;

	return (entry->data);
}

/*
 * dapl_llist_peek_head
 */

void *
dapl_llist_peek_head(DAPL_LLIST_HEAD *head)
{
	DAPL_LLIST_ENTRY *first;

	dapl_os_assert(!dapl_llist_is_empty(head));
	first = *head;
	return (first->data);
}


/*
 * dapl_llist_next_entry
 *
 * Obtain the next entry in the list, return NULL when we get to the
 * head
 */

void *
dapl_llist_next_entry(IN    DAPL_LLIST_HEAD 	*head,
    IN    DAPL_LLIST_ENTRY 	*cur_ent)
{
	DAPL_LLIST_ENTRY *next;

	dapl_os_assert(!dapl_llist_is_empty(head));
	if (cur_ent == NULL) {
		next = *head;
	} else {
		next = cur_ent->flink;
		if (next == *head) {
			return (NULL);
		}
	}
	return (next->data);
}

/*
 * dapl_llist_debug_print_list()
 *
 * Purpose: Prints the linked list for debugging
 */
void
dapl_llist_debug_print_list(DAPL_LLIST_HEAD *head)
{
	DAPL_LLIST_ENTRY * entry;
	DAPL_LLIST_ENTRY * first;
	first = *head;
	if (!first) {
		dapl_dbg_log(DAPL_DBG_TYPE_RTN, "EMPTY_LIST\n");
		return;
	}
	dapl_dbg_log(DAPL_DBG_TYPE_RTN, "HEAD %p\n", *head);
	dapl_dbg_log(DAPL_DBG_TYPE_RTN, "Entry %p %p %p %p\n",
	    first,
	    first->flink,
	    first->blink,
	    first->data);
	entry = first->flink;
	while (entry != first) {
		dapl_dbg_log(DAPL_DBG_TYPE_RTN, "Entry %p %p %p %p\n",
		    entry,
		    entry->flink,
		    entry->blink,
		    entry->data);
		entry = entry->flink;
	}
}
