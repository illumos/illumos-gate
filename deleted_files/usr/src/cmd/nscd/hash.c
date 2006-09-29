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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <synch.h>
#include <memory.h>
#include <getxby_door.h>

static int    hash_string();

hash_t *
make_hash(size)
int size;
{
	hash_t *ptr;

	ptr	= (hash_t *)malloc(sizeof (*ptr));
	ptr->size  =   size;
	ptr->table = (hash_entry_t **)
	    malloc((unsigned) (sizeof (hash_entry_t *) * size));
	(void) memset((char *)ptr->table, (char)0,
	    sizeof (hash_entry_t *)*size);
	ptr->start = NULL;
	ptr->hash_type = String_Key;
	return (ptr);
}

hash_t *
make_ihash(size)
int size;
{
	hash_t *ptr;

	ptr	= (hash_t *)malloc(sizeof (*ptr));
	ptr->size  =   size;
	ptr->table = (hash_entry_t **)malloc((unsigned)
	    (sizeof (hash_entry_t *) * size));
	(void) memset((char *)ptr->table, (char)0,
	    sizeof (hash_entry_t *)*size);
	ptr->start = NULL;
	ptr->hash_type = Integer_Key;
	return (ptr);
}


char **
get_hash(hash_t *tbl, char *key)
{

	int bucket;
	hash_entry_t *tmp;
	hash_entry_t *new;

	if (tbl->hash_type == String_Key) {
		tmp = tbl->table[bucket = hash_string(key, tbl->size)];
	} else {
		tmp = tbl->table[bucket = abs((int)key) % tbl->size];
	}

	if (tbl->hash_type == String_Key) {
		while (tmp != NULL) {
			if (strcmp(tmp->key, key) == 0) {
				return (&tmp->data);
			}
			tmp = tmp->next_entry;
		}
	} else {
		while (tmp != NULL) {
			if (tmp->key == key) {
				return (&tmp->data);
			}
			tmp = tmp->next_entry;
		}
	}

	/*
	 * not found....
	 * insert new entry into bucket...
	 */

	new = (hash_entry_t *)malloc(sizeof (*new));
	new->key = ((tbl->hash_type == String_Key)?strdup(key):key);
	/*
	 * hook into chain from tbl...
	 */
	new->right_entry = NULL;
	new->left_entry = tbl->start;
	tbl->start = new;
	if (new->left_entry != NULL)
		new->left_entry->right_entry = new;
	/*
	 * hook into bucket chain
	 */
	new->next_entry = tbl->table[bucket];
	tbl->table[bucket] = new;
	new->data = NULL;   /* so we know that it is new */
	return (&new->data);
}

char **
find_hash(hash_t *tbl, char *key)
{
	hash_entry_t 	*tmp;

	if (tbl->hash_type == String_Key) {
		tmp = tbl->table[hash_string(key, tbl->size)];
		for (; tmp != NULL; tmp = tmp->next_entry) {
			if (strcmp(tmp->key, key) == 0) {
				return (&tmp->data);
			}
		}
	} else {
		tmp = tbl->table[abs((int)key) % tbl->size];
		for (; tmp != NULL; tmp = tmp->next_entry) {
			if (tmp->key == key) {
				return (&tmp->data);
			}
		}
	}

	return (NULL);
}

char *
del_hash(hash_t *tbl, hash_entry_t *del_this,  hash_entry_t *prev, int bucket)
{
	/*
	 * del_this points to entry marked for deletion, prev to
	 * item preceeding in bucket chain or NULL if del_this is first.
	 * remove from bucket chain first....
	 */
	if (tbl->hash_type == String_Key) {
		free(del_this->key);
	}
	if (prev != NULL) {
		prev->next_entry = del_this->next_entry;
	} else {
		tbl->table[bucket] = del_this->next_entry;
	}
	/*
	 * now remove from tbl chain....
	 */
	if (del_this->right_entry != NULL) { /* not first in chain.... */
		del_this->right_entry->left_entry = del_this->left_entry;
	} else {
		tbl->start = del_this->left_entry;
	}
	if (del_this->left_entry != NULL) { /* not last in chain.... */
		del_this->left_entry->right_entry = del_this->right_entry;
	}
	return (del_this->data);
}

int
operate_hash(hash_t *tbl, void (*ptr)(), char *usr_arg)
{
	hash_entry_t *tmp = tbl->start;
	int c = 0;

	while (tmp) {
		(*ptr)(tmp->data, usr_arg, tmp->key);
		tmp = tmp->left_entry;
		c++;
	}
	return (c);
}

int
operate_hash_addr(hash_t *tbl, void (*ptr)(), char *usr_arg)
{
	hash_entry_t *tmp = tbl->start;
	int c = 0;

	while (tmp) {
		(*ptr)(&(tmp->data), usr_arg, tmp->key);
		tmp = tmp->left_entry;
		c++;
	}
	return (c);
}

void
destroy_hash(hash_t *tbl, int (*ptr)(), char *usr_arg)
{
	hash_entry_t *tmp = tbl->start, *prev;

	while (tmp) {
		if (ptr) {
			(*ptr)(tmp->data, usr_arg, tmp->key);
		}

		if (tbl->hash_type == String_Key) {
			free(tmp->key);
		}
		prev = tmp;
		tmp = tmp->left_entry;
		free((char *)prev);
	}
	free((char *)tbl->table);
	free(tbl);
}

static int
hash_string(char *s, int modulo)
{
	unsigned result = 0;
	int i = 1;

	while (*s != 0) {
		result += (*s++ << i++);
	}

	return (result % modulo);
}

int
reap_hash(hash_t *tbl, nsc_stat_t *admin_ptr, mutex_t *hash_lock,
	int howlong)
{

	hash_entry_t *tmp, *next, *prev;
	uint_t count = 0;
	uint_t bucket;
	uint_t extra_sleep = 1;
	uint_t buckets_per_interval, seconds_per_interval, buckets_togo;
	uint_t total_buckets;
	time_t now;

	/*
	 * We don't want to spend too much time reaping nor too little.
	 * We cap the TTL at 2^28 to prevent overflow. This is 8.5 years,
	 * so we aren't really going to reap anything anyway.
	 * Also, we want the total time to be one second more than the
	 * time to expire the entries.
	 */
	howlong++;
	if (howlong < 32) howlong = 32;
	if (howlong > (1<<28)) howlong = 1<<28;

	/* Total_buckets can range from 37 to 2^30 */
	total_buckets = admin_ptr->nsc_suggestedsize;

	if (total_buckets >= howlong && total_buckets > (howlong>>2)) {
		/*
		 * In the realm of buckets_per_second. total_buckets might
		 * be near 2^30, so we divide first
		 */
		buckets_per_interval = total_buckets/(howlong>>2);
		seconds_per_interval = 4;
	} else if (total_buckets >= howlong) {
		/* Still buckets per second, but it is safe to multiply first */
		buckets_per_interval = (total_buckets<<2)/howlong;
		seconds_per_interval = 4;
	} else if (total_buckets <= (howlong>>2)) {
		/*
		 * Now in the secs/buck realm. Howlong is at least 4 times
		 * total_buckets, so we are safe to use this as the interval.
		 * Figure out the rounding error and sleep it at the end.
		 */
		seconds_per_interval = howlong/total_buckets;
		buckets_per_interval = 1;
		extra_sleep = 1 + howlong -
		    (total_buckets*seconds_per_interval);
	} else {
		/*
		 * Still in secs/buck realm, but seconds_per_interval
		 * is too short. Use 8 as the minimum, then adjust the extra
		 * at the end. We need 8 because of rounding error.
		 */
		seconds_per_interval = (howlong/(total_buckets>>3));
		buckets_per_interval = 8;
		extra_sleep = 1 + howlong -
		    ((total_buckets>>3)*seconds_per_interval);
	}

	/*
	 * bucket keeps track of which bucket in the whole table we are on.
	 * buckets_togo is which bucket in this interval we are on.
	 */

	for (bucket = buckets_togo = 0;
	    bucket < admin_ptr->nsc_suggestedsize;
	    bucket++) {
		if (buckets_togo <= 0) {
			sleep(seconds_per_interval);
			buckets_togo = buckets_per_interval;
			now = time(NULL);
		}
		mutex_lock(hash_lock);
		tmp = tbl->table[bucket];
		prev = NULL;
		while (tmp != NULL) {
			next = tmp->next_entry;
			if (tmp->data == (char *)NULL) {
				del_hash(tbl, tmp, prev, bucket);
				free(tmp);
				count++;
			} else if ((tmp->data != (char *)-1) &&
			    ((((nsc_bucket_t *)(tmp->data))->nsc_status &
			    ST_UPDATE_PENDING) == 0) &&
			    (((nsc_bucket_t *)(tmp->data))->nsc_timestamp
			    < now)) {
				del_hash(tbl, tmp, prev, bucket);
				free(tmp->data);
				free(tmp);
				count++;
				admin_ptr->nsc_entries--;
			} else {
				prev = tmp;
			}
			tmp = next;
		}
		mutex_unlock(hash_lock);
		buckets_togo--;

	}
	sleep(extra_sleep);
	return (count);
}
