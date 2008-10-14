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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <string.h>
#include <stdlib.h>
#include <sys/nsctl/nsc_hash.h>

#define	HASH_PRIME 2039

static int calc_hash(const char *);

hash_node_t **
nsc_create_hash()
{
	hash_node_t **hash;

	hash = (hash_node_t **)calloc(HASH_PRIME, sizeof (hash_node_t *));
	return (hash);
}

int
nsc_insert_node(hash_node_t **hash, void *data, const char *key)
{
	int index;
	hash_node_t *node;

	node = (hash_node_t *)malloc(sizeof (hash_node_t));
	if (!node) {
		return (-1);
	}
	node->key = strdup(key);
	node->data = data;

	/*
	 * possible enhancement would be to search
	 * in this index for a duplicate
	 */
	index = calc_hash(key);
	node->next = hash[ index ];
	hash[ index ] = node;

	return (0);
}

/*
 * lookup
 *
 * Description:
 *	Searches the hash to find a node.
 *
 * Return values:
 *	0 if not found.
 *	pointer to node if found.
 */
void *
nsc_lookup(hash_node_t **hash, const char *key)
{
	int index;
	hash_node_t *node;

	index = calc_hash(key);
	node = hash[ index ];
	while (node) {
		if (strcmp(node->key, key) == 0)
			return (node->data);
		node = node->next;
	}
	return (0);
}

void *
nsc_remove_node(hash_node_t **hash, char *key)
{
	int index;
	hash_node_t *node, *prev;
	void *retval;

	index = calc_hash(key);
	if (!hash[ index ]) {
		return (0);
	}

	if (strcmp(hash[ index ]->key, key) == 0) {
		node = hash[ index ];
		retval = node->data;
		hash[ index ] = hash[ index ]->next;
		free(node->key);
		free(node);
		return (retval);
	}
	prev = hash[ index ];
	node = prev->next;
	while (node && (strcmp(node->key, key) != 0)) {
		prev = node;
		node = node->next;
	}

	/* did we find it? */
	if (node) {
		prev->next = node->next;
		retval = node->data;
		free(node->key);
		free(node);
		return (retval);
	}
	return (0);
}

void
nsc_remove_all(hash_node_t **hash, void (*callback)(void *))
{
	int i;
	hash_node_t *p, *next;

	for (i = 0; i < HASH_PRIME; i++) {
		p = hash[ i ];
		while (p) {
			next = p->next;
			if (callback) {
				callback(p->data);
			}
			free(p->key);
			free(p);
			p = next;
		}
	}
	free(hash);
}

/* ---------------------------------------------------------------------- */

/*
 * Basic rotating hash, as per Knuth.
 */
static int
calc_hash(const char *key)
{
	unsigned int hash, i;
	int len = strlen(key);
	for (hash = len, i = 0; i < len; i++) {
		hash = (hash << 5) ^ (hash >> 27) ^ key[ i ];
	}
	return (hash % HASH_PRIME);
}
