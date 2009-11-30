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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "hashset.h"
#include "mountd.h"
#include <sys/sdt.h>

/*
 * HASHSET is hash table managing pointers to a set of keys
 * (set is a collection without duplicates). The public interface
 * of the HASHSET is similar to the java.util.Set interface.
 * Unlike the libc `hsearch' based hash table, this implementation
 * does allow multiple instances of HASHSET within a single application,
 * and the HASHSET_ITERATOR allows to iterate through the entire set
 * using h_next().
 *
 * HASHSET does not store actual keys but only pointers to keys. Hence the
 * data remains intact when HASHSET grows (resizes itself). HASHSET accesses
 * the actual key data only through the hash and equal functions given
 * as arguments to h_create.
 *
 * Hash collisions are resolved with linked lists.
 */

typedef struct HashSetEntry {
	uint_t e_hash;		/* Hash value */
	const void *e_key;	/* Pointer to a key */
	struct HashSetEntry *e_next;
} ENTRY;

struct HashSet {
	ENTRY **h_table;	/* Pointer to an array of ENTRY'ies */
	uint_t h_tableSize;	/* Size of the array */
	uint_t h_count;		/* Current count */
	uint_t h_threshold;	/* loadFactor threshold */
	float  h_loadFactor;	/* Current loadFactor (h_count/h_tableSize( */
	uint_t (*h_hash) (const void *);
	int    (*h_equal) (const void *, const void *);
};

struct HashSetIterator {
	HASHSET i_h;
	uint_t i_indx;
	ENTRY *i_e;
	uint_t i_coll;
};

static void rehash(HASHSET h);

#define	DEFAULT_INITIALCAPACITY	1
#define	DEFAULT_LOADFACTOR	0.75

/*
 *  Create a HASHSET
 *  - HASHSET is a hash table of pointers to keys
 *  - duplicate keys are not allowed
 *  - the HASHSET is opaque and can be accessed only through the h_ functions
 *  - two keys k1 and k2 are considered equal if the result of equal(k1, k2)
 *    is non-zero
 *  - the function hash(key) is used to compute hash values for keys; if
 *    keys are "equal" the values returned by the hash function must be
 *    identical.
 */

HASHSET
h_create(uint_t (*hash) (const void *),
    int    (*equal) (const void *, const void *),
    uint_t initialCapacity,
    float loadFactor)
{
	HASHSET h;

	if (initialCapacity == 0)
		initialCapacity = DEFAULT_INITIALCAPACITY;

	if (loadFactor < 0.0)
		loadFactor = DEFAULT_LOADFACTOR;

	h = exmalloc(sizeof (*h));

	if (h == NULL)
		return (NULL);

	h->h_table = exmalloc(initialCapacity * sizeof (ENTRY *));

	(void) memset(h->h_table, 0, initialCapacity * sizeof (ENTRY *));

	if (h->h_table == NULL) {
		free(h);
		return (NULL);
	}
	h->h_tableSize = initialCapacity;
	h->h_hash = hash;
	h->h_equal = equal;
	h->h_loadFactor = loadFactor;
	h->h_threshold = (uint_t)(initialCapacity * loadFactor);
	h->h_count = 0;

	return (h);
}

/*
 *  Return a pointer to a matching key
 */

const void *
h_get(const HASHSET h, void *key)
{
	uint_t hash = h->h_hash(key);
	uint_t i = hash % h->h_tableSize;
	ENTRY *e;

	for (e = h->h_table[i]; e; e = e->e_next)
		if (e->e_hash == hash && h->h_equal(e->e_key, key))
			return (e->e_key);

	return (NULL);
}

/*
 *  Rehash (grow) HASHSET
 *  - called when loadFactor exceeds threshold
 *  - new size is 2*old_size+1
 */

static void
rehash(HASHSET h)
{
	uint_t i = h->h_tableSize;
	uint_t newtabSize = 2 * i + 1;
	ENTRY **newtab = exmalloc(newtabSize * sizeof (ENTRY *));

	(void) memset(newtab, 0, newtabSize * sizeof (ENTRY *));

	while (i--) {
		ENTRY *e, *next;

		for (e = h->h_table[i]; e; e = next) {
			uint_t k = e->e_hash % newtabSize;

			next = (ENTRY *) e->e_next;
			e->e_next = (ENTRY *) newtab[k];
			newtab[k] = e;
		}
	}

	h->h_threshold = (uint_t)(newtabSize * h->h_loadFactor);
	h->h_tableSize = newtabSize;
	free(h->h_table);
	h->h_table = newtab;
}

/*
 *  Store a key into a HASHSET
 *  - if there is already an "equal" key then the new key will not
 *    be stored and the function returns a pointer to an existing key
 *  - otherwise the function stores pointer to the new key and return NULL
 */

const void *
h_put(HASHSET h, const void *key)
{
	uint_t hash = h->h_hash(key);
	uint_t indx = hash % h->h_tableSize;
	ENTRY *e;

	for (e = h->h_table[indx]; e; e = e->e_next)
		if (e->e_hash == hash && h->h_equal(e->e_key, key))
			return (key);

	if (h->h_count >= h->h_threshold) {
		rehash(h);

		indx = hash % h->h_tableSize;
	}

	e = exmalloc(sizeof (ENTRY));
	e->e_hash = hash;
	e->e_key = (void *) key;
	e->e_next = h->h_table[indx];

	h->h_table[indx] = e;
	h->h_count++;

	DTRACE_PROBE2(mountd, hashset, h->h_count, h->h_loadFactor);

	return (NULL);
}

/*
 *  Delete a key
 *  - if there is no "equal" key in the HASHSET the fuction returns NULL
 *  - otherwise the function returns a pointer to the deleted key
 */

const void *
h_delete(HASHSET h, const void *key)
{
	uint_t hash = h->h_hash(key);
	uint_t indx = hash % h->h_tableSize;
	ENTRY *e, *prev;

	for (e = h->h_table[indx], prev = NULL; e; prev = e, e = e->e_next) {
		if (e->e_hash == hash && h->h_equal(e->e_key, key)) {
			key = e->e_key;
			if (prev)
				prev->e_next = e->e_next;
			else
				h->h_table[indx] = e->e_next;
			free(e);
			return (key);
		}
	}

	return (NULL);
}

/*
 *  Return an opaque HASHSET_ITERATOR (to be used in h_next())
 */

HASHSET_ITERATOR
h_iterator(HASHSET h)
{
	HASHSET_ITERATOR i = exmalloc(sizeof (*i));

	i->i_h = h;
	i->i_indx = h->h_tableSize;
	i->i_e = NULL;
	i->i_coll = 0;

	return (i);
}

/*
 * Return a pointer to a next key
 */

const void *
h_next(HASHSET_ITERATOR i)
{
	const void *key;

	while (i->i_e == NULL) {
		if (i->i_indx-- == 0)
			return (NULL);

		i->i_e = i->i_h->h_table[i->i_indx];
	}

	key = i->i_e->e_key;
	i->i_e = i->i_e->e_next;

	if (i->i_e)
		i->i_coll++;

	return (key);
}
