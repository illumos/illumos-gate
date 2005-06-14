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
 *	db_index_entry.cc
 *
 *	Copyright (c) 1988-2000 by Sun Microsystems, Inc.
 *	All Rights Reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>

#include "db_headers.h"
#include "db_index_entry.h"
#include "nisdb_mt.h"

/* Constructor:  create an entry using given string and location info. */
db_index_entry::db_index_entry(char* name, int nlen, entryp ep)
{
	if ((key = new item(name, nlen)) == NULL)
		FATAL("db_index_entry::db_index_entry: cannot allocate space",
			DB_MEMORY_LIMIT);
	location = ep;
	next_result = next = NULL;
	/* what about hashval ? */
}

/*
 * Constructor:  create an entry using the given info.
 * A copy of the item is made.  New entry is added to head of list of 'n'.
*/
db_index_entry::db_index_entry(unsigned long hval, item* k,
				entryp ep, db_index_entry_p rest)
{
	if ((key = new item(k)) == NULL)
		FATAL(
		"db_index_entry::db_index_entry: cannot allocate space (2)",
		DB_MEMORY_LIMIT);
	location = ep;
	next = rest;
	next_result = NULL;
	hashval = hval;
}

/*
 * Join two lists (entry as identified by its 'location' occurs on both list,
 * then it is included in the list returned).
 * Returns pointer to resulting list; size of list
 * returned in 'newsize'.  List is chained using the 'nextresult' pointer.
 */
db_index_entry_p
db_index_entry::join(long /* size1 */, long /* size2 */,
	db_index_entry_p list2, long * newsize)
{
	db_index_entry_p mergedlist = NULL, // records that occur on both lists
		mergedtail = NULL, 	// tail pointer of mergedlist
		current,		// current pointer of this list
		other,			// current pointer of updated list2
		otherprev,		// previous pointer of updated list2
		otherstart = list2;	// head of updated list2
	int count = 0;

	/*
	 * algorithm is straightforward:
	 * traverse this list,
	 * for each item, traverse list2,
	 * if item on list1 matches item on list2,
	 * add to merged list and delete it from list2.
	 */

	for (current = this; (current != NULL) && (otherstart != NULL);
					current = current->next_result) {
		/* find 'current' in 'other' list */
		otherprev = NULL;
		for (other = otherstart;
			other != NULL;
			other = other->next_result) {
			if (current->location == other->location)
				break;
			else
				otherprev = other;
		}
		if (other != NULL) { /* found */
			/* delete 'other' from future consideration */
			if (otherprev == NULL) {
				/* new head */
				otherstart = otherstart->next_result;
			} else {
				/* bypass 'other' */
				otherprev->next_result = other->next_result;
			}
			/* add 'current' to list of items found so far */
			if (mergedlist == NULL)
				mergedlist = current;	/* first one found */
			else
				mergedtail->next_result = current; /* append */
			mergedtail = current; /* point to last entry found */
			++count;
		}
	}
	if (mergedtail) mergedtail->next_result = NULL;  /* set end to null */
	*newsize = count;
	return (mergedlist);
}

/* Relocate bucket starting with this entry to new hashtable 'new_tab'. */
void
db_index_entry::relocate(db_index_entry_p *new_tab, unsigned long hashsize)
{
	db_index_entry_p np, next_np, *hp;

	for (np = this; np != NULL; np = next_np) {
		next_np = np->next;
		hp = &new_tab[np->hashval % hashsize];
		np->next = *hp;
		*hp = np;
	}
}

/* Return the next entry in the bucket starting with this entry
	    with the same hashvalue, key and location as this entry. */
db_index_entry_p
db_index_entry::getnext(bool_t casein, unsigned long hval, item *i, entryp l)
{
	db_index_entry_p np;

	for (np = this; np != NULL; np = np->next) {
		if ((np->hashval == hval) &&
	(np->key->equal(i, casein)) && l == location) {
			break;
		}
	}

	if (np != NULL)
		return (np->next);
	else
		return (NULL);
}

/*
 * Return pointer to index entry with same hash value, same key,
 * and same record number as those supplied.  Returns NULL if not found.
 */
db_index_entry_p
db_index_entry::lookup(bool_t casein, unsigned long hval,
			item *i, entryp recnum)
{
	db_index_entry_p np;

	for (np = this; np != NULL; np = np->next) {
		if (np->hashval == hval && np->key->equal(i, casein) &&
			np->location == recnum) {
			break;
		}
	}
	if (np) np->next_result = NULL;  /* should only be 1 */
	return (np);
}

/*
 * Returns pointer to a list of index entries with the same hash value and
 * key as those given.  Returns in 'how_many' the number of entries in the
 * list returned.  The list is linked by the 'next_result' field of the
 * index entries.  These may be changed after the next call to 'lookup'
 * or 'join'.
 */
db_index_entry_p
db_index_entry::lookup(bool_t casein, unsigned long hval,
			item *i, long * how_many)
{
	db_index_entry_p fst, prev, curr;
	long count = 0;

	for (fst = this; fst != NULL; fst = fst->next) {
		if ((fst->hashval == hval) && (fst->key->equal(i, casein))) {
			++count;
			break;
		}
	}
	/*
	 * gather all the ones with the same key; assume that all entries
	 * with same key are located contiguously.
	 */
	if (fst != NULL) {
		prev = fst;
		for (curr = fst->next; curr != NULL; curr = curr->next) {
			if ((curr->hashval == hval) &&
				(curr->key->equal(i, casein))) {
	prev->addresult(curr);
	prev = curr;
	++count;
			}
			else
	break;
		}
		prev->addresult(NULL); /* terminate the list -CM */
	}
	*how_many = count;
	return (fst);
}

/*
 * Remove entry with the specified hashvalue, key, and record number.
 * Returns 'TRUE' if successful, FALSE otherwise.
 * If the entry being removed is at the head of the list, then
 * the head is updated to reflect the removal. The storage for the index
 * entry is freed. The record pointed to by 'recnum' must be removed
 * through another means.  All that is updated in this operation is the
 * index.
 */
bool_t
db_index_entry::remove(db_index_entry_p *head, bool_t casein,
			unsigned long hval, item *i, entryp recnum)
{
	db_index_entry_p np, dp;

	/* Search for it in the bucket */
	for (dp = np = this; np != NULL; np = np->next) {
		if (np->hashval == hval && np->key->equal(i, casein) &&
			np->location == recnum) {
			break;
		} else {
			dp = np;
		}
	}

	if (np == NULL) return FALSE;	// cannot delete if it is not there

	if (dp == np) {
		*head = np->next;	// deleting head of bucket
	} else {
		dp->next = np->next;	// deleting interior link
		}
	delete np;

	return (TRUE);
}

/* Replace the 'location' field of the index entry with the given one. */
/*
void
db_index_entry::replace(entryp ep)
{
	location = ep;
}
*/

/*
 * Create and add an entry with the given hashvalue, key value, and record
 * location, to the bucket pointed to by 'hashvalue'.
 * If an entry with the same hashvalue and key value is found,
 * the entry is added after the first entry with this property.  Otherwise,
 * the entry is added to the head of the bucket.  This way, entries
 * with the same hashvalue and key are not scattered throughout the bucket
 * but they occur together. Copy is made of given key.
 */
bool_t
db_index_entry::add(db_index_entry **head, bool_t casein,
			unsigned long hval, item *i, entryp recnum)

{
	db_index_entry_p curr, prev, rp, save;

	/* Search for it in the bucket */
	for (prev = curr = this; curr != NULL; curr = curr->next) {
		if (curr->hashval == hval && curr->key->equal(i, casein)) {
			break;
		} else {
			prev = curr;
		}
	}



	if (curr == NULL) {
		/* none with same hashvalue/key found. Add to head of list. */
		save = *head;
		*head = new db_index_entry(hval, i, recnum, * head);
		if (*head == NULL) {
			*head = save;	// restore previous state
			FATAL3(
			"db_index_entry::add: cannot allocate space for head",
			DB_MEMORY_LIMIT, FALSE);
		}
	} else {
		/* Found same hashvalue/key.  Add entry after that one. */
		save = prev->next;
		prev->next = new db_index_entry(hval, i, recnum, prev->next);
		if (prev->next == NULL) {
			prev->next = save; // restore previous state
			FATAL3(
			"db_index_entry::add: cannot allocate space for entry",
			DB_MEMORY_LIMIT, FALSE);
		}
	}

	return (TRUE);
}

/* Print this entry to stdout. */
void
db_index_entry::print()
{
	if (key != NULL) {
			key->print();
			printf("\t");
		}
	printf(": %d\n", location);
}

/* Print bucket starting with this entry. */
void
db_index_entry::print_all()
{
	db_index_entry *np;
	for (np = this; np != NULL; np = np->next) {
		np->print();
		}
}

/* Print result list starting with this entry. */
void
db_index_entry::print_results()
{
	db_index_entry *np;
	for (np = this; np != NULL; np = np->next_result) {
		np->print();
		}
}
