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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdlib.h>
#include <assert.h>
#include <pthread.h>

#include "sip_hash.h"

/*
 * This file implements functions that add, search or remove an object
 * from the hash table. The object is opaque to the hash functions. To add
 * an object to the hash table, the caller provides the hash table,
 * the object and the index into the hash table. To search an object,
 * the caller provides the hash table, the digest (opaque), the index into
 * the hash table and the function that does the actual match. Similarly,
 * for removing an object, the caller provides the hash table, the digest
 * (opaque), the index into the hash table and the function that does
 * the acutal deletion of the object - if the deletion is successful,
 * the object is taken off of the hash table.
 */

/*
 * Given an object and the hash index, add it to the given hash table
 */
int
sip_hash_add(sip_hash_t	*sip_hash, void *obj, int hindex)
{
	sip_hash_obj_t	*new_obj;
	sip_hash_t	*hash_entry;

	assert(obj != NULL);

	new_obj = (sip_hash_obj_t *)malloc(sizeof (*new_obj));
	if (new_obj == NULL)
		return (-1);
	new_obj->sip_obj = obj;
	new_obj->next_obj = NULL;
	new_obj->prev_obj = NULL;
	hash_entry = &sip_hash[hindex];
	(void) pthread_mutex_lock(&hash_entry->sip_hash_mutex);
	if (hash_entry->hash_count == 0) {
		assert(hash_entry->hash_head == NULL);
		assert(hash_entry->hash_tail == NULL);
		hash_entry->hash_head = new_obj;
	} else {
		hash_entry->hash_tail->next_obj = new_obj;
		new_obj->prev_obj = hash_entry->hash_tail;
	}
	hash_entry->hash_tail = new_obj;
	hash_entry->hash_count++;
	(void) pthread_mutex_unlock(&hash_entry->sip_hash_mutex);
	return (0);
}

/*
 * Given the hash table, the digest to be searched for,  index into the hash
 * table and the function to do the actual matching, return the object,
 * if found.
 */
void *
sip_hash_find(sip_hash_t *sip_hash, void *digest, int hindex,
    boolean_t (*match_func)(void *, void *))
{
	int		count;
	sip_hash_obj_t	*tmp;
	sip_hash_t	*hash_entry;

	hash_entry =  &sip_hash[hindex];
	(void) pthread_mutex_lock(&hash_entry->sip_hash_mutex);
	tmp = hash_entry->hash_head;
	for (count = 0; count < hash_entry->hash_count; count++) {
		if (match_func(tmp->sip_obj, digest)) {
			(void) pthread_mutex_unlock(
			    &hash_entry->sip_hash_mutex);
			return (tmp->sip_obj);
		}
		tmp = tmp->next_obj;
	}
	(void) pthread_mutex_unlock(&hash_entry->sip_hash_mutex);
	return (NULL);
}

/*
 * Walk the hash table and invoke func on each object. 'arg' is passed
 * to 'func'
 */
void
sip_walk_hash(sip_hash_t *sip_hash, void (*func)(void *, void *), void *arg)
{
	sip_hash_t	*hash_entry;
	int		count;
	int		hcount;
	sip_hash_obj_t	*tmp;

	for (count = 0; count < SIP_HASH_SZ; count++) {
		hash_entry =  &sip_hash[count];
		(void) pthread_mutex_lock(&hash_entry->sip_hash_mutex);
		tmp = hash_entry->hash_head;
		for (hcount = 0; hcount < hash_entry->hash_count; hcount++) {
			assert(tmp->sip_obj != NULL);
			func(tmp->sip_obj, arg);
			tmp = tmp->next_obj;
		}
		(void) pthread_mutex_unlock(&hash_entry->sip_hash_mutex);
	}
}

/*
 * Given the hash table, the digest to be searched for,  the index into the
 * hash table and the  delete function provided to do the actual deletion,
 * remove the object from the hash table (i.e. only if the object is deleted).
 */
void
sip_hash_delete(sip_hash_t *sip_hash, void *digest, int hindex,
    boolean_t (*del_func)(void *, void *, int *))
{
	sip_hash_t	*hash_entry;
	int		count;
	sip_hash_obj_t	*tmp;
	int		found;

	hash_entry =  &sip_hash[hindex];
	(void) pthread_mutex_lock(&hash_entry->sip_hash_mutex);
	tmp = hash_entry->hash_head;
	for (count = 0; count < hash_entry->hash_count; count++) {
		if (del_func(tmp->sip_obj, digest, &found)) {
			if (tmp == hash_entry->hash_head) {
				if (tmp->next_obj != NULL) {
					hash_entry->hash_head = tmp->next_obj;
					tmp->next_obj->prev_obj = NULL;
				} else {
					assert(hash_entry->hash_tail ==
					    hash_entry->hash_head);
					hash_entry->hash_head = NULL;
					hash_entry->hash_tail = NULL;
				}
			} else {
				sip_hash_obj_t	*next = tmp->next_obj;

				if (next != NULL) {
					tmp->prev_obj->next_obj = next;
					next->prev_obj = tmp->prev_obj;
				} else {
					assert(hash_entry->hash_tail == tmp);
					tmp->prev_obj->next_obj = NULL;
					hash_entry->hash_tail =
					    tmp->prev_obj;
				}
			}
			tmp->prev_obj = NULL;
			tmp->next_obj = NULL;
			free(tmp);
			hash_entry->hash_count--;
			(void) pthread_mutex_unlock(
			    &hash_entry->sip_hash_mutex);
			return;
		/*
		 * If we found the object, we are done
		 */
		} else if (found == 1) {
			(void) pthread_mutex_unlock(
			    &hash_entry->sip_hash_mutex);
			return;
		}
		tmp = tmp->next_obj;
	}
	(void) pthread_mutex_unlock(&hash_entry->sip_hash_mutex);
}
