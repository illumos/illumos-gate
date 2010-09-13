/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2002-2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <ipp/ipgpc/filters.h>

/* table structure used for exact-match classification of selectors */

/* Statics */
static int ht_hash(int);
static linked_list ht_search(hash_table, int);
static void remove_num_inserted(table_id_t *);

/*
 * ht_hash(a)
 *
 * hash function for keys (a) of type int
 */
static int
ht_hash(int a)
{
	return (a % TABLE_SIZE);
}

/*
 * ht_insert(taid, id, key)
 *
 * inserts id into table with filter_id as the value
 * if key == taid->wildcard, the key is inserted as a wildcard
 * statistics are updated after insert is successful
 * returns DONTCARE_VALUE if key == wildcard, NORMAL_VALUE otherwise
 */
int
ht_insert(table_id_t *taid, key_t id, int key)
{
	int x;
	ht_node_t *p;
	hash_table table = taid->table;

	/* check if dontcare */
	if (key == taid->wildcard) {
		/* don't cares/wildcards are not inserted */
		++taid->stats.num_dontcare;
		return (DONTCARE_VALUE);
	}

	x = ht_hash(key);
	/*
	 * insert if key matches and entry is being used or if entry is empty
	 */
	if (((table[x].key == key) && (table[x].info == 1)) ||
	    (table[x].info == 0)) {
		table[x].key = key;
		table[x].info = 1;
		(void) ipgpc_list_insert(&table[x].elements, id);
	} else if (table[x].next == NULL) {
		table[x].next = kmem_cache_alloc(ht_node_cache, KM_SLEEP);
		table[x].next->elements = NULL;
		table[x].next->next = NULL;
		table[x].next->key = key;
		table[x].next->info = 1;
		(void) ipgpc_list_insert(&table[x].next->elements, id);
	} else {
		p = table[x].next;
		while (p != NULL) {
			if (((p->key == key) && (p->info == 1)) ||
			    (p->info == 0)) {
				p->key = key;
				p->info = 1;
				(void) ipgpc_list_insert(&p->elements, id);
				if (taid->info.dontcareonly == B_TRUE) {
					taid->info.dontcareonly = B_FALSE;
				}
				return (NORMAL_VALUE);
			}
			p = p->next;
		}
		p = kmem_cache_alloc(ht_node_cache, KM_SLEEP);
		p->elements = NULL;
		p->next = NULL;
		p->key = key;
		p->info = 1;
		(void) ipgpc_list_insert(&p->elements, id);
		p->next = table[x].next;
		table[x].next = p->next;
	}
	/* update stats */
	++taid->stats.num_inserted;
	if (taid->info.dontcareonly == B_TRUE) {
		taid->info.dontcareonly = B_FALSE;
	}
	return (NORMAL_VALUE);
}

/*
 * ht_search(table, key)
 *
 * searches for key and returns the linked list value associated with key if
 * found in table. NULL is returned if key not found
 */
static linked_list
ht_search(hash_table table, int key)
{
	int x;
	ht_node_t *p = NULL;

	x = ht_hash(key);
	if ((table[x].key == key) && (table[x].info == 1)) {
		return (table[x].elements);
	} else {
		p = table[x].next;
		while (p != NULL) {
			if ((p->key == key) && (p->info == 1)) {
				return (p->elements);
			}
			p = p->next;
		}
		return (NULL);
	}
}

/*
 * ht_retrieve(taid, key, fid_table)
 *
 * All exact matches and wildcard matches are collected and inserted
 * into the fid_table
 * the number of found filters that match the input key are returned
 * returns (-1) if memory error
 */
int
ht_retrieve(table_id_t *taid, int key, ht_match_t *fid_table)
{
	int num_found = 0;
	linked_list alist = NULL;
	hash_table table = taid->table;

	/* dontcare/wildcards are not inserted */
	if (key == taid->wildcard) {
		return (0);
	} else {
		alist = ht_search(table, key);
		if (alist != NULL) {
			if ((num_found = ipgpc_mark_found(taid->info.mask,
			    alist, fid_table)) == -1) {
				return (-1); /* signifies memory error */
			}
		}
	}
	return (num_found);
}

/*
 * remove_num_inserted(taid)
 *
 * updates the num_inserted statistics along with reseting the dontcareonly
 * flag when applicable and decrementing the total inserted
 */
static void
remove_num_inserted(table_id_t *taid)
{
	--taid->stats.num_inserted;
	if (taid->stats.num_inserted <= 0) {
		taid->info.dontcareonly = B_TRUE;
	}
}

/*
 * ht_remove(taid, id, key)
 *
 * removes a single filter id item from the linked_list associated with id in
 * table
 */
void
ht_remove(table_id_t *taid, key_t id, int key)
{
	hash_table table = taid->table;
	int x;
	ht_node_t *p;
	ht_node_t *t;

	/* check if dontcare */
	if (key == taid->wildcard) {
		/* don't cares/wildcards are not inserted */
		--taid->stats.num_dontcare;
		return;
	}
	x = ht_hash(key);
	/* remove entry if key matches and entry is being used */
	if ((table[x].key == key) && (table[x].info == 1)) {
		if (table[x].elements != NULL) {
			if (ipgpc_list_remove(&table[x].elements, id)) {
				/* update stats */
				remove_num_inserted(taid);
			}
		}
		if (table[x].elements == NULL) {
			/* reclaim memory if possible */
			if (table[x].next != NULL) {
				table[x].elements = table[x].next->elements;
				table[x].info = table[x].next->info;
				table[x].key = table[x].next->key;
				p = table[x].next; /* use p as temp */
				table[x].next = table[x].next->next;
				kmem_cache_free(ht_node_cache, p);
			} else {
				table[x].info = 0; /* mark entry as empty */
				table[x].key = 0;
			}
		}
	} else {
		p = &table[x];
		while (p->next != NULL) {
			if ((p->next->key == key) && (p->next->info == 1)) {
				if (ipgpc_list_remove(&p->next->elements, id)) {
					/* update stats */
					remove_num_inserted(taid);
				}
				if (p->next->elements == NULL) {
					/* reclaim memory if possible */
					if (p->next->next == NULL) {
						kmem_cache_free(ht_node_cache,
						    p->next);
						p->next = NULL;
					} else {
						t = p->next;
						p->next = p->next->next;
						kmem_cache_free(ht_node_cache,
						    t);
					}
				}
				return;
			}
			p = p->next;
		}
	}
}
