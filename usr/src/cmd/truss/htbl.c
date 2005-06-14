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
 * Copyright 2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <synch.h>
#include <thread.h>
#include <memory.h>
#include <assert.h>
#include <libproc.h>
#include "ramdata.h"
#include "proto.h"
#include "htbl.h"


htbl_t *
init_hash(unsigned int size)
{
	htbl_t *htp;
	hashb_t *temp;
	int i;

	if ((size & (size - 1)) != 0)
		abend("Size must be power of two", NULL);

	htp = (htbl_t *)my_malloc(sizeof (htbl_t), NULL);
	htp->size = size;
	htp->tbl = (hashb_t *)
	    my_calloc((size_t)size, sizeof (hashb_t), NULL);

	/* Init mutexes */
	for (i = 0; i < size; i++) {
		temp = &htp->tbl[i];
		(void) mutex_init(&temp->block, USYNC_THREAD, NULL);
	}

	return (htp);
}

void
destroy_hash(htbl_t *htp)
{
	int i;
	hentry_t *tmp;
	hentry_t *prev;
	hashb_t *cur;

	for (i = 0; i < htp->size; i++) {
		cur = &htp->tbl[i];
		(void) mutex_destroy(&cur->block);
		tmp = cur->first;

		while (tmp != NULL) {
			prev = tmp;
			tmp = tmp->next;

			free(prev->key);
			prev->key = NULL;
			free(prev->lib);
			prev->lib = NULL;

			free((char *)prev);
			if (tmp != NULL)
				tmp->prev = NULL;
		}
	}
	free((char *)htp->tbl);
	htp->tbl = NULL;
	free(htp);
}

static unsigned int
hash_str(char *str, unsigned int sz)
{
	uint_t hash = 0;
	uint_t g;
	char *p;

	assert(str != NULL);
	for (p = str; *p != '\0'; p++) {
		hash = (hash << 4) + *p;
		if ((g = (hash & 0xf0000000)) != 0) {
			hash ^= (g >> 24);
			hash ^= g;
		}
	}

	return (hash & (sz - 1));
}


void
add_fcall(htbl_t *htp, char *lib, char *key, unsigned long cnt)
{
	unsigned int bucket;
	hentry_t *tmp;
	hentry_t *new;
	hashb_t *cur;

	bucket = hash_str(key, htp->size);
	cur = &htp->tbl[bucket];

	(void) mutex_lock(&cur->block);

	tmp = cur->first;
	while (tmp != NULL) {
		if (strcmp(tmp->key, key) == 0) {
			if (strcmp(tmp->lib, lib) == 0) {
				tmp->count += cnt;
				(void) mutex_unlock(&cur->block);
				return;
			}
		}
		tmp = tmp->next;
	}

	/*
	 * If we're still here, there was no such fcall recorded
	 * so we make a new entry and add it to the table
	 */

	new = (hentry_t *)my_malloc(sizeof (hentry_t), NULL);
	new->key = strdup(key);
	if (new->key == NULL)
		abend("Out of memory in htbl.c", NULL);
	new->lib = strdup(lib);
	if (new->lib == NULL)
		abend("Out of memory in htbl.c", NULL);
	new->count = cnt;
	new->prev = NULL;
	new->next = cur->first;
	tmp = new->next;
	if (tmp != NULL) {
		tmp->prev = new;
	}
	cur->first = new;

	(void) mutex_unlock(&cur->block);
}

/*
 * iterate_hash locks the table and returns an enumeration struct
 * using this it is possible to iterate through the entries of a hash table
 * once finished, use iter_free to unlock the table and free the struct
 */

hiter_t *
iterate_hash(htbl_t *tbl)
{
	int b;
	int i;
	hiter_t *new;
	hashb_t *cur;
	hentry_t *tmp = NULL;

	new = (hiter_t *)my_malloc(sizeof (hiter_t), NULL);
	new->table = tbl;

	for (i = 0; i < tbl->size; i++) {
		cur = &tbl->tbl[i];
		(void) mutex_lock(&cur->block);
		if (tmp == NULL) {
			tmp = cur->first;
			b = i;
		}
	}

	new->next = tmp;
	new->bucket = b;

	return (new);
}

void
iter_free(hiter_t *itr)
{
	int i;
	hashb_t *cur;
	htbl_t *tbl;

	tbl = itr->table;
	for (i = 0; i < tbl->size; i++) {
		cur = &tbl->tbl[i];
		(void) mutex_unlock(&cur->block);
	}

	free(itr);
}

hentry_t *
iter_next(hiter_t *itr)
{
	int i;
	hentry_t *tmp;
	hentry_t *ret;
	hashb_t *cur = NULL;
	htbl_t *hash;

	ret = itr->next;


	if (ret == NULL)
		return (ret);

	hash = itr->table;
	tmp = ret->next;
	i = itr->bucket;

	if (tmp == NULL) {
		for (i = i + 1; i < hash->size; i++) {
			cur = &hash->tbl[i];
			tmp = cur->first;
			if (tmp != NULL)
				break;
		}
	}

	itr->next = tmp;
	itr->bucket = i;

	return (ret);
}

size_t
elements_in_table(htbl_t *tbl)
{
	size_t elem = 0;
	hiter_t *itr = iterate_hash(tbl);
	hentry_t *tmp = iter_next(itr);
	while (tmp != NULL) {
		elem++;
		tmp = iter_next(itr);
	}
	iter_free(itr);
	return (elem);
}
