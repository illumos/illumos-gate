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
 * Copyright (c) 1996, 2010, Oracle and/or its affiliates. All rights reserved.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <synch.h>
#include <memory.h>
#include "hash.h"

static int    hash_string(const char *, long);

hash *
make_hash(size_t size)
{
	hash	*ptr;

	ptr = malloc(sizeof (*ptr));
	ptr->size = size;
	ptr->table = malloc((size_t)(sizeof (hash_entry *) * size));
	(void) memset((char *)ptr->table, 0, sizeof (hash_entry *) * size);
	ptr->start = NULL;
	ptr->hash_type = String_Key;
	return (ptr);
}

hash *
make_ihash(size_t size)
{
	hash	*ptr;

	ptr = malloc(sizeof (*ptr));
	ptr->size = size;
	ptr->table = malloc(sizeof (hash_entry *) * size);
	(void) memset((char *)ptr->table, 0, sizeof (hash_entry *) * size);
	ptr->start = NULL;
	ptr->hash_type = Integer_Key;
	return (ptr);
}

char **
get_hash(hash *tbl, char *key)
{
	long		bucket;
	hash_entry	*tmp, *new;

	if (tbl->hash_type == String_Key) {
		tmp = tbl->table[bucket = hash_string(key, tbl->size)];
	} else {
		tmp = tbl->table[bucket = labs((long)key) % tbl->size];
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
	new = malloc(sizeof (*new));
	new->key = ((tbl->hash_type == String_Key)?strdup(key):key);

	/*
	 * hook into chain from tbl...
	 */
	new->right_entry = NULL;
	new->left_entry = tbl->start;
	tbl->start = new;

	/*
	 * hook into bucket chain
	 */
	new->next_entry = tbl->table[bucket];
	tbl->table[bucket] = new;
	new->data = NULL;		/* so we know that it is new */
	return (&new->data);
}

char **
find_hash(hash *tbl, const char *key)
{
	hash_entry 	*tmp;

	if (tbl->hash_type == String_Key) {
		tmp = tbl->table[hash_string(key, tbl->size)];
		for (; tmp != NULL; tmp = tmp->next_entry) {
			if (strcmp(tmp->key, key) == 0) {
				return (&tmp->data);
			}
		}
	} else {
		tmp = tbl->table[labs((long)key) % tbl->size];
		for (; tmp != NULL; tmp = tmp->next_entry) {
			if (tmp->key == key) {
				return (&tmp->data);
			}
		}
	}
	return (NULL);
}

char *
del_hash(hash *tbl, const char *key)
{
	ulong_t bucket;
	hash_entry * tmp, * prev = NULL;

	if (tbl->hash_type == String_Key) {
		bucket = hash_string(key, tbl->size);
	} else {
		bucket = labs((long)key) % tbl->size;
	}

	if ((tmp = tbl->table[bucket]) == NULL) {
		return (NULL);
	} else {
		if (tbl->hash_type == String_Key) {
			while (tmp != NULL) {
				if (strcmp(tmp->key, key) == 0) {
					break;  /* found item to delete ! */
				}
				prev = tmp;
				tmp  = tmp->next_entry;
			}
		} else {
			while (tmp != NULL) {
				if (tmp->key == key) {
					break;
				}
				prev = tmp;
				tmp  = tmp->next_entry;
			}
		}
		if (tmp == NULL) {
			return (NULL); /* not found */
		}
	}

	/*
	 * tmp now points to entry marked for deletion, prev to
	 * item preceding in bucket chain or NULL if tmp is first.
	 * remove from bucket chain first....
	 */
	if (tbl->hash_type == String_Key) {
		free(tmp->key);
	}
	if (prev != NULL) {
		prev->next_entry = tmp->next_entry;
	} else {
		tbl->table[bucket] = tmp->next_entry;
	}

	/*
	 * now remove from tbl chain....
	 */
	if (tmp->right_entry != NULL) { /* not first in chain.... */
		tmp->right_entry->left_entry = (tmp->left_entry ?
		    tmp->left_entry->right_entry: NULL);
	} else {
		tbl->start = (tmp->left_entry ?tmp->left_entry->right_entry:
		    NULL);
	}
	return (tmp->data);
}

size_t
operate_hash(hash *tbl, void (*ptr)(), const char *usr_arg)
{
	hash_entry	*tmp = tbl->start;
	size_t		c = 0;

	while (tmp) {
		(*ptr)(tmp->data, usr_arg, tmp->key);
		tmp = tmp->left_entry;
		c++;
	}
	return (c);
}

size_t
operate_hash_addr(hash *tbl, void (*ptr)(), const char *usr_arg)
{
	hash_entry	*tmp = tbl->start;
	size_t		c = 0;

	while (tmp) {
		(*ptr)(&(tmp->data), usr_arg, tmp->key);
		tmp = tmp->left_entry;
		c++;
	}
	return (c);
}

void
destroy_hash(hash *tbl, int (*ptr)(), const char *usr_arg)
{
	hash_entry * tmp = tbl->start, * prev;

	while (tmp) {
		if (ptr) {
			(void) (*ptr)(tmp->data, usr_arg, tmp->key);
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
hash_string(const char *s, long modulo)
{
	unsigned int	result = 0;
	int		i = 1;

	while (*s != '\0') {
		result += (*s++ << i++);
	}

	/* LINTED */
	return ((int)(result % modulo));
}
