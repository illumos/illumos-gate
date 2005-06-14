/*
 * Copyright (c) 1993-2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Copyright 1988, 1991 by Carnegie Mellon University
 *
 * All Rights Reserved
 *
 * Permission to use, copy, modify, and distribute this software and its
 * documentation for any purpose and without fee is hereby granted, provided
 * that the above copyright notice appear in all copies and that both that
 * copyright notice and this permission notice appear in supporting
 * documentation, and that the name of Carnegie Mellon University not be used
 * in advertising or publicity pertaining to distribution of the software
 * without specific, written prior permission.
 *
 * CARNEGIE MELLON UNIVERSITY DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS
 * SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS.
 * IN NO EVENT SHALL CMU BE LIABLE FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL
 * DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR
 * PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS
 * ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF
 * THIS SOFTWARE.
 */

/*
 * Generalized hash table ADT
 *
 * Provides multiple, dynamically-allocated, variable-sized hash tables on
 * various data and keys.
 *
 * This package attempts to follow some of the coding conventions suggested
 * by Bob Sidebotham and the AFS Clean Code Committee of the
 * Information Technology Center at Carnegie Mellon.
 *
 * Additions for per bucket locking, and configurable dynamic free of
 * unused entries.
 */

#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/sysmacros.h>
#include <stdarg.h>
#include <stddef.h>
#include <assert.h>
#include <synch.h>
#include "dhcpd.h"
#include "hash.h"

/*
 * Hash table size calculation routine.
 *
 * Estimate the size of a hash table based on the expected number of
 * entries, up to a maximum of HASHTABLESIZE.
 */
static unsigned
hashi_Hsize(unsigned hint)
{
	unsigned f;

	if (hint == 0)				/* Default size. */
		hint = HASHTABLESIZE;
	else if (hint < 16)			/* Minimal size. */
		hint = 16;

	hint /= 4;
	for (f = 2; f * f <= hint; f++) {	/* Find next largest prime. */
		if (hint % f == 0) {
			f = 1;
			hint++;
		}
	}
	return (MIN(HASHTABLESIZE, hint));
}

/*
 * Frees an entire linked list of bucket members (used in the
 * open hashing scheme).  Does nothing if the passed pointer is NULL.
 *
 * Returns B_FALSE and members which could not be freed in bucketptr, when
 * force variable is set to B_FALSE, and free_data routine indicates
 * free did not occur.
 */
static boolean_t
hashi_FreeMember(hash_member **bucketptr, boolean_t (*free_data)(),
    boolean_t force)
{
	hash_member *prev, *next, *unfree = NULL;
	boolean_t ret = B_TRUE;

	if (bucketptr) {
		for (prev = *bucketptr; prev; prev = next) {
			next = prev->next;
			prev->next = NULL;
			if (free_data != NULL) {
				if ((*free_data)(prev->data, force) ==
				    B_FALSE) {
					ret = B_FALSE;
					prev->next = unfree;
					unfree = prev;
				} else {
					free(prev);
				}
			} else
				free(prev);
		}
		*bucketptr = unfree;
	}
	return (ret);
}

/*
 * Dynamic free initialization.
 */
static void
hashi_Dinit(hash_tbl *hashtable, hash_member *memberptr)
{
	(void) mutex_init(&memberptr->h_mtx, USYNC_THREAD, NULL);
	memberptr->h_time = time(NULL) + hashtable->dfree_time;
	memberptr->h_count = 1;
}

/*
 * Dynamic free reference count increment.
 */
static void
hashi_Dhold(hash_member *memberptr)
{
	(void) mutex_lock(&memberptr->h_mtx);
	memberptr->h_count++;
	(void) mutex_unlock(&memberptr->h_mtx);
}

/*
 * Dynamic free expired data. Return NULL if memberptr is successfully
 * dynamically freed, otherwise return memberptr.
 */
static hash_member *
hashi_Dfree(hash_member *memberptr, boolean_t (*free_data)())
{
	hash_member *next;

	next = memberptr->next;
	memberptr->next = NULL;
	if (hashi_FreeMember(&memberptr, free_data, B_FALSE) == B_TRUE)
		memberptr = NULL;
	else
		memberptr->next = next;
	return (memberptr);
}

/*
 * Hash table initialization routine.
 *
 * This routine creates and intializes a hash table of size "tablesize"
 * entries.  Successful calls return a pointer to the hash table (which must
 * be passed to other hash routines to identify the hash table).  Failed
 * calls return NULL.
 */
hash_tbl *
hash_Init(unsigned tablesize, boolean_t (*dfree_data)(), time_t dtime,
	boolean_t lck)
{
	hash_tbl *hashtblptr;
	unsigned totalsize;
	unsigned	i;

	tablesize = hashi_Hsize(tablesize);

	totalsize = sizeof (hash_tbl) + (sizeof (hash_bucket) *
	    (tablesize - 1));

	hashtblptr = (hash_tbl *)smalloc(totalsize);

	hashtblptr->size = tablesize; /* Success! */
	hashtblptr->bucketnum = 0;
	hashtblptr->dfree_data = dfree_data;
	hashtblptr->dfree_lck = lck;
	hashtblptr->dfree_time = dtime;
	hashtblptr->table = &hashtblptr->data[0];
	for (i = 0; i < tablesize; i++) {
		hashtblptr->table[i].table = hashtblptr;
		if (lck == B_TRUE) {
			(void) rwlock_init(&(hashtblptr->table[i].rwlock),
			    USYNC_THREAD, NULL);
		}
	}

	return (hashtblptr);		/* NULL if failure */
}

/*
 * Generic hash function to calculate a hash code from the given string.
 *
 * For each byte of the string, this function left-shifts the value in an
 * accumulator and then adds the byte into the accumulator.  The contents of
 * the accumulator is returned after the entire string has been processed.
 * It is assumed that this result will be used as the "hashcode" parameter in
 * calls to other functions in this package.  These functions automatically
 * adjust the hashcode for the size of each hashtable.
 *
 * This algorithm probably works best when the hash table size is a prime
 * number.
 *
 * Hopefully, this function is better than the previous one which returned
 * the sum of the squares of all the bytes.  I'm still open to other
 * suggestions for a default hash function.  The programmer is more than
 * welcome to supply his/her own hash function as that is one of the design
 * features of this package.
 */
static unsigned
hashi_HashFunction(unsigned char *string, unsigned len)
{
	unsigned accum;

	/*
	 * Special case: allow hash_Delete() to iterate over buckets.
	 */
	if (string == NULL)
		return (len);

	for (accum = 0; len != 0; len--) {
		accum <<= 1;
		accum += (unsigned)(*string++ & 0xFF);
	}
	return (accum);
}

/*
 * This routine re-initializes the hash table.  It frees all the allocated
 * memory and resets all bucket pointers to NULL. For the macro hash
 * table, the table will be reused. Other tables (with bucket locks)
 * will be destroyed.
 */
void
hash_Reset(hash_tbl *hashtable, boolean_t (*free_data)())
{
	hash_bucket	*bucketptr;
	unsigned	i;

	bucketptr = &((hashtable->table)[0]);
	for (i = 0; i < hashtable->size; i++) {
		if (hashtable->dfree_lck == B_TRUE)
			(void) rw_wrlock(&bucketptr->rwlock);
		/*
		 * Unequivocally free member, using the force parameter.
		 */
		(void) hashi_FreeMember(&bucketptr->next, free_data, B_TRUE);
		bucketptr->next = NULL;
		if (hashtable->dfree_lck == B_TRUE) {
			(void) rw_unlock(&bucketptr->rwlock);
			(void) rwlock_destroy(&(bucketptr->rwlock));
		}
		bucketptr++;
	}
	hashtable->bucketnum = 0;
}

/*
 * Returns B_TRUE if at least one entry for the given key exists; B_FALSE
 * otherwise. Dynamically free expired data as searched.
 */
static int
hashi_Exists(hash_bucket *bucketptr, int (*compare)(), hash_datum *key,
    boolean_t (*free_data)(), hash_member **prev)
{
	hash_member *prevptr = (hash_member *)bucketptr;
	hash_member *memberptr = bucketptr->next;
	hash_tbl *hashtable = bucketptr->table;
	hash_member *next;
	boolean_t ret = B_FALSE;
	time_t now = time(NULL);

	while (memberptr != NULL) {
		/*
		 * Dynamically free expired data.
		 */
		if (free_data != NULL && hashtable->dfree_data != NULL &&
		    memberptr->h_time < now) {
			next = memberptr->next;
			if ((memberptr = hashi_Dfree(memberptr, free_data)) ==
			    NULL) {
				prevptr->next = memberptr = next;
				continue;
			}
		}

		/*
		 * Entry exists, or we are randomly selecting any
		 * element (compare function is NULL).
		 */
		if (compare == NULL || (*compare)(key, memberptr->data)) {
			ret = B_TRUE;
			break;
		} else
			prevptr = memberptr;
		memberptr = memberptr->next;
	}

	if (prev != NULL)
		*prev = prevptr;
	return (ret);
}

/*
 * Returns number of Dynamically freed expired entries.
 */
static int
hashi_Expire(hash_bucket *bucketptr, boolean_t (*free_data)())
{
	hash_member *prevptr = (hash_member *)bucketptr;
	hash_member *memberptr = bucketptr->next;
	hash_tbl *hashtable = bucketptr->table;
	hash_member *next;
	int rcount = 0;
	time_t now = time(NULL);

	while (memberptr) {
		/*
		 * Dynamically free expired data.
		 */
		if (free_data != NULL && hashtable->dfree_data != NULL &&
		    memberptr->h_time < now) {
			next = memberptr->next;
			if ((memberptr = hashi_Dfree(memberptr, free_data)) ==
			    NULL) {
				rcount++;
				prevptr->next = memberptr = next;
				continue;
			}
		}
		prevptr = memberptr;
		memberptr = memberptr->next;
	}
	return (rcount);
}

/*
 * Insert the data item "element" into the hash table using "hashcode"
 * to determine the bucket number, and "compare" and "key" to determine
 * its uniqueness.
 *
 * If the insertion is successful the element is returned.  If a matching entry
 * already exists in the given bucket of the hash table, then NULL is returned,
 * signifying that the entry is already in the table. This happens when some
 * other thread has already inserted the entry.
 */
void *
hash_Insert(hash_tbl *hashtable, void *hashdata, unsigned hashlen,
    int (*compare)(), hash_datum *key, hash_datum *element)
{
	hash_member *temp = NULL;
	hash_bucket *bucketptr;
	hash_member *prev = NULL;
	unsigned hashcode = hashi_HashFunction(hashdata, hashlen);

	bucketptr = &((hashtable->table)[hashcode % hashtable->size]);
	if (hashtable->dfree_lck)
		(void) rw_wrlock(&bucketptr->rwlock);

	if (hashi_Exists(bucketptr, compare, key, hashtable->dfree_data,
	    &prev)) {
		/* Some other thread got there first, so just return */
		if (hashtable->dfree_lck)
			(void) rw_unlock(&bucketptr->rwlock);
		return (NULL);
	}

	temp = (hash_member *)smalloc(sizeof (hash_member));

	prev->next = temp;
	temp->data = element;
	temp->next = NULL;

	/*
	 * Dynamic free initialization.
	 */
	if (hashtable->dfree_data != NULL)
		hashi_Dinit(hashtable, temp);

	if (hashtable->dfree_lck)
		(void) rw_unlock(&bucketptr->rwlock);

	return ((void *)temp);
}

/*
 * Release the reference count on an item. Performance: if item is to be
 * deleted, mark for future dynamic free.
 */
void
hash_Rele(void *hashp, boolean_t delete)
{
	hash_member *memberptr = (hash_member *)hashp;

	(void) mutex_lock(&memberptr->h_mtx);
	memberptr->h_count--;
	assert(memberptr->h_count >= 0);
	if (delete == B_TRUE)
		memberptr->h_time = 0;
	(void) mutex_unlock(&memberptr->h_mtx);
}

/*
 * Report the reference count on an item.
 */
int
hash_Refcount(void *hashp)
{
	hash_member *memberptr = (hash_member *)hashp;
	int ret;

	(void) mutex_lock(&memberptr->h_mtx);
	ret = memberptr->h_count;
	(void) mutex_unlock(&memberptr->h_mtx);
	return (ret);
}

/*
 * Report the dynamic free time on an item.
 */
int
hash_Htime(void *hashp)
{
	hash_member *memberptr = (hash_member *)hashp;
	int ret;

	(void) mutex_lock(&memberptr->h_mtx);
	ret = memberptr->h_time;
	(void) mutex_unlock(&memberptr->h_mtx);
	return (ret);
}

/*
 * Increase the dynamic free time on an item.
 */
void
hash_Age(void *hashp)
{
	hash_member *memberptr = (hash_member *)hashp;

	(void) mutex_lock(&memberptr->h_mtx);
	memberptr->h_time++;
	(void) mutex_unlock(&memberptr->h_mtx);
}

/*
 *  Set the dynamic free time on an item.
 */
void
hash_Dtime(void *hashp, time_t tm)
{
	hash_member *memberptr = (hash_member *)hashp;

	(void) mutex_lock(&memberptr->h_mtx);
	memberptr->h_time = tm;
	(void) mutex_unlock(&memberptr->h_mtx);
}

/*
 * Delete a data item from the hash table using "hashcode"
 * to determine the bucket number, and "compare" and "key" to determine
 * its uniqueness.
 *
 * If the deletion is successful 0 is returned.  If a matching entry
 * does not exist in the given bucket of the hash table, or some other error
 * occurs, -1 is returned and the insertion is not done.
 */
boolean_t
hash_Delete(hash_tbl *hashtable, void *hashdata, unsigned hashlen,
    int (*compare)(), hash_datum *key, boolean_t (*free_data)())
{
	hash_member *prev = NULL;
	hash_member *temp;
	hash_bucket *bucketptr;
	unsigned hashcode = hashi_HashFunction(hashdata, hashlen);

	bucketptr = &((hashtable->table)[hashcode % hashtable->size]);
	if (hashtable->dfree_lck == B_TRUE)
		(void) rw_wrlock(&bucketptr->rwlock);

	if (hashi_Exists(bucketptr, compare, key, free_data, &prev) ==
	    B_FALSE || prev == NULL) {
		if (hashtable->dfree_lck == B_TRUE)
			(void) rw_unlock(&bucketptr->rwlock);
		return (B_FALSE); /* Entry does not exist */
	}

	temp = prev->next;
	if (temp) {
		prev->next = temp->next;
		temp->next = NULL;
		(void) hashi_FreeMember(&temp, free_data, B_TRUE);
	} else
		prev->next = NULL;
	if (hashtable->dfree_lck == B_TRUE)
		(void) rw_unlock(&bucketptr->rwlock);
	return (B_TRUE);
}

/*
 * Locate and return the data entry associated with the given key.
 *
 * If the data entry is found, a pointer to it is returned.  Otherwise,
 * NULL is returned.
 */
hash_datum *
hash_Lookup(hash_tbl *hashtable, void *hashdata, unsigned hashlen,
    int (*compare)(), hash_datum *key, boolean_t hold)
{
	hash_datum *ret = NULL;
	hash_bucket *bucketptr;
	hash_member *prev = NULL;
	unsigned hashcode = hashi_HashFunction(hashdata, hashlen);

	bucketptr = &((hashtable->table)[hashcode % hashtable->size]);
	if (hashtable->dfree_lck == B_TRUE)
		(void) rw_wrlock(&bucketptr->rwlock);

	if (hashi_Exists(bucketptr, compare, key, hashtable->dfree_data,
	    &prev) == B_TRUE) {
		/*
		 * Dynamic free increment reference.
		 */
		if (hold)
			hashi_Dhold(prev->next);
		ret = prev->next->data;

	}
	if (hashtable->dfree_lck == B_TRUE)
		(void) rw_unlock(&bucketptr->rwlock);
	return (ret);
}

/*
 * Reap expired data items, or a random data item from the hash table.
 */
void
hash_Reap(hash_tbl *hashtable, boolean_t (*free_data)())
{
	hash_bucket		*bucketptr;
	int			rcount;
	unsigned		i;

	bucketptr = &((hashtable->table)[0]);
	rcount = 0;

	/*
	 * Walk the buckets, reaping expired clients.
	 */
	for (i = 0; i < hashtable->size; i++) {
		if (hashtable->dfree_lck == B_TRUE)
			(void) rw_wrlock(&bucketptr->rwlock);
		rcount += hashi_Expire(bucketptr, hashtable->dfree_data);
		if (hashtable->dfree_lck == B_TRUE)
			(void) rw_unlock(&bucketptr->rwlock);
		bucketptr++;
	}

	/*
	 * Nothing to be reaped, delete a random element. Note that
	 * the unhash_data routine will wait for current references
	 * before deletion.
	 */
	if (rcount == 0) {
		for (i = 0; i < hashtable->size; i++) {
			if (hash_Delete(hashtable, NULL, i, NULL, NULL,
			    free_data) == B_TRUE) {
				break;
			}
		}
	}
}
