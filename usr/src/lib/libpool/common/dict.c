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
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * This file contains a basic dictionary implementation which stores
 * arbitrary key-value mappings. It is used by libpool to store
 * information about element pointers (pool_elem_t) in the kernel
 * provider implementation.
 */

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>

#include "dict.h"

/*
 * HASH_64_INIT is the same as the INIT value since it is the value
 * used by FNV (FNV1_64_INIT). More details on FNV are available at:
 *
 * http://www.isthe.com/chongo/tech/comp/fnv/index.html
 */
#define	HASH_64_INIT	(0xcbf29ce484222325ULL) /* Hash initializer */

/*
 * HASH_64_PRIME is a large prime number chosen to minimize hashing
 * collisions.
 */
#define	HASH_64_PRIME	(0x100000001b3ULL)	/* Large Prime */

/*
 * DICT_SIZE is chosen as it is the nearest prime to 2^9 (512). 512 is
 * chosen as it is unlikely that this dictionary will contain more
 * elements than this in normal operation. Of course overflow in each
 * bucket is acceptable, but if there is too much overflow, then
 * performance will degrade to that of a list.
 */
#define	DICT_SIZE	509			/* Reasonable prime */

/*
 * Data Types
 */

/*
 * A key bucket.
 */
typedef struct dict_bucket
{
	const void		*db_key;	/* key */
	void			*db_value;	/* value */
	struct dict_bucket	*db_next;	/* next bucket */
} dict_bucket_t;

/*
 * A dictionary which holds a mapping between a key and a value.
 *	dh_change	- detects changes to the dictionary.
 *	dh_cmp		- comparison function
 *	dh_hash		- hashing function
 *	dh_buckets	- key storage
 *	dh_size		- # of buckets
 */
struct dict_hdl {
	uint64_t		dh_change;
	int			(*dh_cmp)(const void *, const void *);
	uint64_t		(*dh_hash)(const void *);
	uint64_t		dh_length;
	dict_bucket_t		**dh_buckets;
	uint64_t		dh_size;
};

/*
 * Utility functions. Mainly used for debugging
 */

#if defined(DEBUG)

static void		bit_print_32(unsigned int);
static void		bit_print_64(unsigned long long);

#endif /* DEBUG */

/*
 * Default functions for hashing and comparing if the user does not specify
 * these values when creating the dictionary.
 */
static int		cmp_addr(const void *, const void *);
static uint64_t		hash_addr(const void *);

/*
 * static functions
 */

#if defined(DEBUG)

/*
 * Print to standard out the bit representation of the supplied value
 */
void
bit_print_32(unsigned int v)
{
	int i, mask = 1 << 31;

	for (i = 1; i <= 32; i++) {
		(void) putchar(((v & mask) == 0) ? '0' : '1');
		v <<= 1;
		if (i % 8 == 0 && i != 32)
			(void) putchar(' ');
	}
	(void) putchar('\n');
}

/*
 * Print to standard out the bit representation of the supplied value
 */
void
bit_print_64(unsigned long long v)
{
	long long mask = 1ll << 63;
	int i;

	for (i = 1; i <= 64; i++) {
		(void) putchar(((v & mask) == 0) ? '0' : '1');
		v <<= 1;
		if (i % 8 == 0 && i != 64)
			(void) putchar(' ');
	}
	(void) putchar('\n');
}



#endif /* DEBUG */

/*
 * Default comparison function which is used if no comparison function
 * is supplied when the dictionary is created. The default behaviour
 * is to compare memory address.
 */
int
cmp_addr(const void *x, const void *y)
{
	return (x != y);
}


/*
 * The default hashing function which is used if no hashing function
 * is provided when the dictionary is created. The default behaviour
 * is to use the hash_buf() function.
 */
uint64_t
hash_addr(const void *key)
{
	return (hash_buf(&key, sizeof (key)));
}


/*
 * public interface
 */

/*
 * Return a hash which is built by manipulating each byte in the
 * supplied data. The hash logic follows the approach suggested in the
 * FNV hash.
 */
uint64_t
hash_buf(const void *buf, size_t len)
{
	uchar_t *start = (uchar_t *)buf;
	uchar_t *end = start + len;
	uint64_t hash = HASH_64_INIT;

	while (start < end) {
		hash *= HASH_64_PRIME;
		hash ^= (uint64_t)*start++;
	}

	return (hash);
}


/*
 * Return a hash which is built by manipulating each byte in the
 * supplied string. The hash logic follows the approach suggested in
 * the FNV hash.
 */
uint64_t
hash_str(const char *str)
{
	uchar_t *p = (uchar_t *)str;
	uint64_t hash = HASH_64_INIT;

	while (*p) {
		hash *= HASH_64_PRIME;
		hash ^= (uint64_t)*p++;
	}

	return (hash);
}

/*
 * Return the number of keys held in the supplied dictionary.
 */
uint64_t
dict_length(dict_hdl_t *hdl)
{
	return (hdl->dh_length);
}

/*
 * Free the supplied dictionary and all it's associated resource.
 */
void
dict_free(dict_hdl_t **hdl)
{
	if ((*hdl)->dh_length > 0) {
		uint64_t i;
		for (i = 0; i < (*hdl)->dh_size; i++) {
			dict_bucket_t *this, *next;
			for (this = (*hdl)->dh_buckets[i]; this != NULL;
			    this = next) {
				next = this->db_next;
				free(this);
			}
		}
	}
	free((*hdl)->dh_buckets);
	free((*hdl));
	*hdl = NULL;
}

/*
 * Create a new dictionary using the supplied comparison and hashing
 * functions. If none are supplied then the defaults are used.
 */
dict_hdl_t *
dict_new(int (*cmp)(const void *, const void *),
    uint64_t (*hash)(const void *))
{
	dict_hdl_t *hdl;

	if ((hdl = calloc(1, sizeof (dict_hdl_t))) == NULL)
		return (NULL);
	hdl->dh_size = DICT_SIZE;
	if ((hdl->dh_buckets = calloc(hdl->dh_size, sizeof (dict_bucket_t *)))
	    == NULL) {
		free(hdl);
		return (NULL);
	}
	hdl->dh_cmp = cmp ? cmp : cmp_addr;
	hdl->dh_hash = hash ? hash : hash_addr;
	return (hdl);
}

/*
 * Get a value from the hash. Null is returned if the key cannot be
 * found.
 */
void *
dict_get(dict_hdl_t *hdl, const void *key)
{
	uint64_t i;
	dict_bucket_t *bucket;

	i = (*hdl->dh_hash)(key)%hdl->dh_size;
	for (bucket = hdl->dh_buckets[i]; bucket != NULL;
	    bucket = bucket->db_next)
		if ((*hdl->dh_cmp)(key, bucket->db_key) == 0)
			break;
	return (bucket ? bucket->db_value : NULL);
}

/*
 * Put an entry into the hash. Null is returned if this key was not
 * already present, otherwise the previous value is returned.
 */
void *
dict_put(dict_hdl_t *hdl, const void *key, void *value)
{
	uint64_t i;
	dict_bucket_t *bucket;
	void *prev = NULL;

	i = (*hdl->dh_hash)(key)%hdl->dh_size;
	for (bucket = hdl->dh_buckets[i]; bucket != NULL;
	    bucket = bucket->db_next)
		if ((*hdl->dh_cmp)(key, bucket->db_key) == 0)
			break;
	if (bucket) {
		prev = bucket->db_value;
	} else {
		bucket = malloc(sizeof (dict_bucket_t));
		bucket->db_key = key;
		bucket->db_next = hdl->dh_buckets[i];
		hdl->dh_buckets[i] = bucket;
		hdl->dh_length++;
	}
	hdl->dh_change++;
	bucket->db_value = value;
	return (prev);
}

/*
 * Remove the key/value from the dictionary. The value is returned if
 * the key is found. NULL is returned if the key cannot be located.
 */
void *
dict_remove(dict_hdl_t *hdl, const void *key)
{
	uint64_t i;
	dict_bucket_t	**pbucket;

	hdl->dh_change++;
	i = (*hdl->dh_hash)(key)%hdl->dh_size;

	for (pbucket = &hdl->dh_buckets[i]; *pbucket != NULL;
	    pbucket = &(*pbucket)->db_next) {
		if ((*hdl->dh_cmp)(key, (*pbucket)->db_key) == 0) {
			dict_bucket_t *bucket = *pbucket;
			void *value = bucket->db_value;

			*pbucket = bucket->db_next;
			free(bucket);
			hdl->dh_length--;
			return (value);
		}
	}
	return (NULL);
}

/*
 * For all entries in the dictionary call the user supplied function
 * (apply) with the key, value and user supplied data. If the
 * dictionary is modifed while this function is executing, then the
 * function will fail with an assertion about table modifcation.
 */
void
dict_map(dict_hdl_t *hdl, void (*apply)(const void *, void **, void *),
    void *cl)
{
	uint64_t i;
	dict_bucket_t *bucket = NULL;
	uint64_t change_stamp = hdl->dh_change;

	for (i = 0; i < hdl->dh_size; i++) {
		for (bucket = hdl->dh_buckets[i]; bucket != NULL;
		    bucket = bucket->db_next) {
			apply(bucket->db_key, &bucket->db_value, cl);
			if (hdl->dh_change != change_stamp)
				assert(!"table modified illegally");
		}
	}
}
