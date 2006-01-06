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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * GENERIC hash functions for NIS names.
 *
 * These functions provide a basic hashing mechanisim for efficiently
 * looking up NIS names. The hashing function is __name_hash() and
 * it hashes into a fixed size hash table of 64 entries. Collisions
 * are dealt with by a "link" pointer to the next entry with the same
 * key. The number 64 was chosen as a compromise between good hashing
 * efficiency and memory usage. Large groups are expected to be about
 * 1024 members which hash down to about 8 entries per table. With a
 * mean search time of 4 name compares this gives us the desired
 * performance.
 * The hash table is augmented by a doubly linked list which points to
 * all entries (used when enumerating groups).
 */

#include "mt.h"
#include <string.h>
#include <ctype.h>
#include <malloc.h>
#include <syslog.h>
#define	__NIS_PRIVATE_INTERFACES
#include <rpcsvc/nis.h>

/*
 * LOWER(c) -- macro implementation of tolower(c), possibly more efficient.
 *
 * NOTA BENISSIME:
 *	Do NOT use this with side-effecting arguments such as LOWER(*s1++);
 *	either use the tolower() function or fix the arguments so they're
 *	side-effect-free (and cheap to evaluate, or this macro will lose).
 */
#define	LOWER(c) (isupper((c)) ? _tolower((c)) : (c))

/*
 * find_item(name, table) -- finds the item called <name> in <table>, or
 *   returns a pointer to the right place to insert an item with that name
 *   (the two cases are distinguished by whether the "right place" contains
 *   NULL).
 */
static NIS_HASH_ITEM **
find_item(nis_name name, NIS_HASH_TABLE *table, int *keyp)
{
	int		key = 0;
	unsigned char	*s;
	NIS_HASH_ITEM	*it;
	NIS_HASH_ITEM	**pp;

	/* At this level we assume name, table != 0 */

	for (s = (unsigned char *)name;  *s != 0;  s++) {
		key += LOWER(*s);
	}
	key %= (sizeof (table->keys) / sizeof (table->keys[0]));

	if (keyp != 0) {
		*keyp = key;
	}
	for (pp = &table->keys[key];  (it = *pp) != 0;  pp = &it->next) {
		if (strcasecmp(name, it->name) == 0) {
			break;
		}
	}
	return (pp);
}

/*
 * Keep this just in case someone actually uses this interface.
 */
int
nis_in_table(
	nis_name	name,	/* NIS name to find 	*/
	NIS_HASH_TABLE	*table,	/* Hash table to use	*/
	int		*key)	/* pointer for key	*/
{
	return (name != 0 && table != 0 && *find_item(name, table, key) != 0);
}

/*
 * nis_insert_item()
 *
 * This function inserts the passed item into a hash table as pointed
 * to by table. It returns 1 if the item was inserted or 0 if the item
 * could not be inserted (because of an identically named
 * item in the table.
 */
int
nis_insert_item(
	NIS_HASH_ITEM	*item,		/* item to insert 	*/
	NIS_HASH_TABLE	*table)		/* Hash table to use	*/
{
	int		key;
	NIS_HASH_ITEM	**pp;

	if (item == 0 || item->name == 0 || table == 0)
		return (0);

	if (0 != *(pp = find_item(item->name, table, &key)))
		return (0); /* Already in the table */

	/* Insert the item into the hash table, */
	item->next	 = *pp;	/* We know it's 0, but hey... */
	*pp		 = item;
	item->keychain   = key;

	/* Insert the item into the serial, doubly linked list */
	if (table->first)
		table->first->prv_item = item;

	item->nxt_item = table->first;
	item->prv_item = NULL; 		/* Head of the list */
	table->first   = item;
	return (1);
}

/*
 * __nis_find_item()
 *
 * This function will find a named NIS_HASH_ITEM in the indicated
 * hash table. It returns either NULL if the item doesn't exist,
 * or a pointer to the item.
 */
NIS_HASH_ITEM *
nis_find_item(
	nis_name	name,	/* NIS name of item remove	*/
	NIS_HASH_TABLE	*table)	/* Hash table			*/
{
	if (name == 0 || table == 0)
		return (0);
	return (*find_item(name, table, (int *)0));
}

/*
 *  nis_pop_item()
 *
 * This function pops the next NIS_ITEM struct off of the chain and
 * returns it. (same as a remove item but doesn't require the user
 * to pass it a name.)
 */
NIS_HASH_ITEM *
nis_pop_item(NIS_HASH_TABLE *table)
{
	NIS_HASH_ITEM	*item, *cur, *prev;

	if (! table)
		return (NULL);

	if (! table->first)
		return (NULL);

	item = table->first;
	prev = NULL;
	for (cur = table->keys[item->keychain]; cur;
			prev = cur, cur = cur->next) {
		if (cur == item) {
			if (prev)
				prev->next = cur->next;
			else
				table->keys[cur->keychain] = cur->next;
			if (cur->prv_item)
				/* ==== error; this shouldn't happen */
				cur->prv_item->nxt_item = cur->nxt_item;
			else
				table->first = cur->nxt_item;
			if (cur->nxt_item)
				cur->nxt_item->prv_item = cur->prv_item;
			break;
		}
	}
	/* ASSERT (cur == item) */
	return (item);
}

/*
 * nis_remove_item()
 *
 * This function will remove a named NIS_HASH_ITEM from the indicated
 * hash table and serial list. It returns either NULL if the
 * item did not exist, or a pointer to the item which can then
 * be freed by the calling function.
 */
NIS_HASH_ITEM *
nis_remove_item(
	nis_name	name,	/* NIS name of item remove	*/
	NIS_HASH_TABLE	*table)	/* Hash table			*/
{
	NIS_HASH_ITEM	**pp;
	NIS_HASH_ITEM	*nl;

	if (name == 0 || table == 0)
		return (0);
	pp = find_item(name, table, (int *)0);
	nl = *pp;
	if (nl == 0)
		return (0);
	/* Remove nl from the hash chain */
	*pp = nl->next;
	nl->next = 0;	/* A little insurance */
	/* Remove nl from the linked list of all names */
	if (nl->prv_item)
		nl->prv_item->nxt_item = nl->nxt_item;
	else
		table->first = nl->nxt_item;
	if (nl->nxt_item)
		nl->nxt_item->prv_item = nl->prv_item;
	nl->prv_item = 0;	/* More insurance */
	nl->nxt_item = 0;

	return (nl);
}

static void		/* A fine candidate for inlining */
free_name_item(NIS_HASH_ITEM *item)
{
	free(item->name);
	free(item);
}

/*
 * nis_flush_table()
 *
 * This simple function will free all of the memory associated with
 * a given table. It may be used to dump caches.
 */
void
nis_flush_table(
	NIS_HASH_TABLE	*table,
	void		(*flush_func)(NIS_HASH_ITEM *))
{
	NIS_HASH_ITEM	*it;

	if (table == 0)
		return;
	if (flush_func == 0) {
		/*
		 * Assumes that 'it' and it->name were malloc()ed, and
		 *   that nothing else was malloc()ed.
		 */
		flush_func = free_name_item;
	}
	while ((it = nis_pop_item(table)) != NULL)
		(*flush_func)(it);
}

/*
 * insert_name()
 *
 * This function inserts the requested name into the hash table
 * at the appropriate place.
 */
void
nis_insert_name(
	nis_name	name,		/* NIS name to insert 	*/
	NIS_HASH_TABLE	*table)		/* Hash table to use	*/
{
	NIS_HASH_ITEM	*nl;

	nl = (NIS_HASH_ITEM *)malloc(sizeof (*nl));
	if (!nl) {
		syslog(LOG_WARNING, "nislib:insert_name out of memory.");
		return;
	}
	nl->name = (nis_name) strdup((char *)(name));
	if (!nl->name) {
		syslog(LOG_WARNING, "nislib:insert_name out of memory.");
		free(nl);
		return;
	}
	if (!nis_insert_item(nl, table)) {
		free_name_item(nl);
	}

}

/*
 * remove_name()
 *
 * This function will remove a name from the hash table
 * and fix up any has chains as appropriate.
 */
void
nis_remove_name(
	nis_name	name,	/* NIS name to remove	*/
	NIS_HASH_TABLE	*table)	/* Hash table		*/
{

	NIS_HASH_ITEM	*nl;

	nl = nis_remove_item(name, table);
	if (nl)
		free_name_item(nl);
}

/*
 * Remove all names from a table.
 */
void
nis_flush_namelist(
	NIS_HASH_TABLE	*table)
{
	nis_flush_table(table, free_name_item);
}

/*
 * nis_scan_table() -- iterate over all items in a hash table.
 *   We ignore first/prv_item/nxt_item and scan in hash-chain order.
 *   The iterator function should *not* insert or delete items.
 */
void
nis_scan_table(
	NIS_HASH_TABLE	*table,
	bool_t		(*func)(NIS_HASH_ITEM *, void *),
	void		*funcarg)
{
	int slot;

	if (table == 0) {
		return;
	}
	for (slot = 0;
	    slot < sizeof (table->keys) / sizeof (table->keys[0]);
	    slot++) {
		NIS_HASH_ITEM *it;

		for (it = table->keys[slot];  it != 0;  it = it->next) {
			if (TRUE == (*func)(it, funcarg)) {
				return;
			}
		}
	}
}
