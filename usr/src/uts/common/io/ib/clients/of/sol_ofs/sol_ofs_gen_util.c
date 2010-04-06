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
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*
 *
 * NAME: gen_util.c
 *
 * DESC: Generic kernel utility functions
 *
 */

#include <sys/types.h>
#include <sys/debug.h>
#include <sys/kmem.h>
#include <sys/ib/clients/of/sol_ofs/sol_ofs_common.h>

/*
 * Doubly linked per user context IB resource list definitions
 * Protection must occur * outside of the list.
 */

/*
 * add_genlist()
 *
 * Adds the entry to the tail of the list.
 */
genlist_entry_t *
add_genlist(genlist_t *list, uintptr_t data, void *data_context)
{

	genlist_entry_t *new_entry;

	new_entry = (genlist_entry_t *)(kmem_zalloc(sizeof (genlist_entry_t),
	    KM_SLEEP));

	if (new_entry != NULL) {
		new_entry->data_context	= data_context;
		new_entry->data	= data;
		new_entry->next	= NULL;
		new_entry->prev	= list->tail;

		if (!list->count) {
			list->tail = new_entry;
			list->head = new_entry;
		} else {
			list->tail->next = new_entry;
			list->tail = new_entry;
		}
		list->count++;
	}
	return (new_entry);
}

/*
 * delete_genlist() - delete the specified entry from the list.
 */
void delete_genlist(genlist_t *list, genlist_entry_t *entry) {

	ASSERT(entry);

	if (entry->prev) {
		entry->prev->next = entry->next;
	} else {
		list->head = entry->next;
	}

	if (entry->next) {
		entry->next->prev = entry->prev;
	} else {
		list->tail = entry->prev;
	}

	list->count--;
	entry->prev = entry->next = NULL;
	kmem_free((void *)entry, sizeof (genlist_entry_t));
}

/*
 * remove_genlist_head() - remove the entry from the list head, but
 *			    don't delete it.
 */
genlist_entry_t *remove_genlist_head(genlist_t *list) {

	genlist_entry_t *entry = list->head;

	if (list->head) {
		list->head = list->head->next;
		list->count--;

		if (!list->head)
			list->tail = list->head;
	}

	return (entry);
}

/*
 * flush_genlist
 */
void flush_genlist(genlist_t *list) {

	genlist_entry_t	*entry;

	entry = remove_genlist_head(list);

	while (entry) {
		kmem_free((void *)entry, sizeof (genlist_entry_t));
		entry = remove_genlist_head(list);
	}
	init_genlist(list);
}

bool genlist_empty(genlist_t *list) {

	if (list->head != NULL)
		return (FALSE);
	else
		return (TRUE);
}

/*
 * FUNCTION: insert_genlist_tail()
 */
void insert_genlist_tail(genlist_t *list, genlist_entry_t *entry) {

	entry->next = NULL;
	entry->prev = list->tail;

	if (!list->count) {
		list->tail = entry;
		list->head = entry;
	} else {
		list->tail->next = entry;
		list->tail = entry;
	}
	list->count++;
}
