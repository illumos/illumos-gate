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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "nscd_db.h"

/*
 * This file implements the database functionality used by the
 * switch and configuration components. The implementation is
 * based on hash and has table. If the need arises in the future,
 * the code in this file can be changed to use other algorithms.
 * The following lists the functions implemented:
 *
 * _nscd_add_db_entry
 * _nscd_delete_db_entry
 * _nscd_get_db_entry
 * _nscd_alloc_db
 * _nscd_free_db
 * _nscd_walk_db
 * _nscd_delete_db_entry_cookie
 */

/*
 * This structure defines an instance of the hash entry
 * which implements the nscd database entry. The
 * db_entry field should always be the first one in
 * the structure.
 */
typedef struct nscd_hash {
	nscd_db_entry_t		db_entry;
	struct nscd_hash	*next_p;
	struct nscd_hash	*prev_p;
} nscd_hash_t;

/*
 * This structure defines a nscd database which
 * is implemented as an array of nscd_hash_t.
 */
struct nscd_db_s {
	int		array_size; /* number of elements in hash_tbl_p */
	nscd_hash_t	**hash_tbl_p;
};

/*
 * This cookie structure is used to iterate through the
 * database entries contained in a nscd database.
 */
struct cookie {
	int		idx;	/* the current bucket */
	nscd_hash_t	*hash;	/* the current hash entry */
	nscd_db_t	*db;    /* the database */
};

/*
 * FUNCTION: calc_hash
 *
 * Calculate a hash for a string based on the elf_hash
 * algorithm, hash is case insensitive. Uses tolower
 * instead of _tolower because of I18N.
 */
static unsigned long
calc_hash(
	const char	*str)
{
	unsigned int	hval = 0;
	char		ch;

	while (*str != '\0') {
		unsigned int	g;

		ch = (char)*str++;
		if (isupper(ch))
			ch = _tolower(ch);
		hval = (hval << 4) + ch;
		if ((g = (hval & 0xf0000000)) != 0)
			hval ^= g >> 24;
		hval &= ~g;
	}
	return ((unsigned long)hval);
}

/*
 * FUNCTION: scan_hash
 *
 * Scan a hash table for a matching hash entry. Assume 'str' is
 * not NULL. If option is NSCD_GET_NEXT_DB_ENTRY and id_num
 * is less than zero, then treats the option as NSCD_GET_FIRST_DB_ENTRY.
 */

static const nscd_hash_t *
scan_hash(
	int			type,
	const char		*str,
	const nscd_hash_t	*idx_p,
	nscd_db_option_t	option,
	int			id_num)
{
	int			id_matched = 0;
	nscd_db_entry_t		*db_entry;

	while (idx_p != NULL) {
		db_entry = &((nscd_hash_t *)idx_p)->db_entry;
		if (db_entry->type == type) {
			if (strcasecmp(str, db_entry->name) == 0) {
				switch (option) {
				case NSCD_GET_FIRST_DB_ENTRY:
					return (idx_p);
				case NSCD_GET_EXACT_DB_ENTRY:
					if (id_num == db_entry->id_num)
						return (idx_p);
					break;
				case NSCD_GET_NEXT_DB_ENTRY:
					if (id_num < 0)
						return (idx_p);
					if (id_matched == 1)
						return (idx_p);
					if (id_num == db_entry->id_num)
						id_matched = 1;
					break;
				}
			}
		}
		idx_p = idx_p->next_p;
	}
	return (NULL);
}

/*
 * FUNCTION: _nscd_get_db_entry
 *
 * Find a nscd database entry from a nscd database.
 */
const nscd_db_entry_t *
_nscd_get_db_entry(
	const nscd_db_t		*db,
	int			type,
	const char		*str,
	nscd_db_option_t	option,
	int			id_num)
{
	unsigned long		hash;
	const nscd_hash_t	*idx_p, *hash_p;

	if (db == NULL || str == NULL)
		return (NULL);

	hash = calc_hash(str);
	idx_p = db->hash_tbl_p[hash % db->array_size];

	hash_p = scan_hash(type, str, idx_p, option, id_num);

	return (&hash_p->db_entry);
}

/*
 * FUNCTION: _nscd_add_db_entry
 *
 * Add a nscd database entry to a nscd database. This function
 * is not MT safe. The caller should lock the database to
 * prevent concurrent updates done by other threads.
 */
nscd_rc_t
_nscd_add_db_entry(
	nscd_db_t		*db,
	const char		*str,
	nscd_db_entry_t		*entry,
	nscd_db_option_t	option)
{
	int			i;
	unsigned long		hash;
	nscd_hash_t		*next_p = NULL, *prev_p = NULL;
	nscd_hash_t		*idx_p, *hash_entry;
	nscd_db_entry_t		*db_entry;

	/* find the bucket */
	hash = calc_hash(str);
	i = hash % db->array_size;
	idx_p = db->hash_tbl_p[i];

	/* can not replace nothing */
	if (idx_p == NULL)
		if (option == NSCD_ADD_DB_ENTRY_REPLACE)
			return (NSCD_DB_ENTRY_NOT_FOUND);

	while (idx_p != NULL) {
		db_entry = &idx_p->db_entry;
		switch (option) {

		case NSCD_ADD_DB_ENTRY_FIRST:
			next_p = idx_p;
			goto add_entry;

		case NSCD_ADD_DB_ENTRY_REPLACE:
			if (db_entry->type != entry->type)
				goto cont;
			if (strcasecmp(db_entry->name, str) != 0)
				goto cont;

			if (db_entry->id_num == entry->id_num) {
				prev_p = idx_p->prev_p;
				next_p = idx_p->next_p;
				free(idx_p);
				goto add_entry;
			}
			goto cont;

		case NSCD_ADD_DB_ENTRY_IF_NONE:
			if (db_entry->type != entry->type)
				break;
			if (strcasecmp(db_entry->name, str) != 0)
				break;
			return (NSCD_DB_ENTRY_FOUND);
		}

		if (idx_p->next_p == NULL) {
			if (option == NSCD_ADD_DB_ENTRY_LAST ||
			    option == NSCD_ADD_DB_ENTRY_IF_NONE) {
				prev_p = idx_p;
				goto add_entry;
			}
		}

		cont:
		idx_p = idx_p->next_p;
	}

	add_entry:

	/*
	 * the nscd_entry_t field should be the first field
	 * in a nscd_hash_t
	 */
	hash_entry = (nscd_hash_t *)entry;

	/* update the prev link list */
	hash_entry->prev_p = prev_p;
	if (prev_p == NULL)
		db->hash_tbl_p[i] = hash_entry;
	else
		prev_p->next_p = hash_entry;

	/* update the next link list */
	hash_entry->next_p = next_p;
	if (next_p != NULL)
		next_p->prev_p = hash_entry;

	return (NSCD_SUCCESS);
}

/*
 * FUNCTION: _nscd_delete_db_entry
 *
 * Delete a nscd database entry from a nscd database. This
 * function is not MT safe. The caller should lock the
 * database to prevent concurrent updates done by other
 * threads.
 */
nscd_rc_t
_nscd_delete_db_entry(
	nscd_db_t		*db,
	int			type,
	const char		*str,
	nscd_db_option_t	option,
	int			id_num)
{
	int			i;
	int			del_more = 0;
	unsigned long		hash;
	nscd_hash_t		*idx_p, *next_p = NULL, *prev_p = NULL;
	nscd_db_entry_t		*db_entry;

	/* find the bucket */
	hash = calc_hash(str);
	i = hash % db->array_size;
	idx_p = db->hash_tbl_p[i];

	/* delete nothing always works */
	if (idx_p == NULL)
		return (NSCD_SUCCESS);

	while (idx_p != NULL) {
		db_entry = &idx_p->db_entry;
		if (db_entry->type != type)
			goto cont;
		if (strcasecmp(db_entry->name, str) != 0)
			goto cont;

		switch (option) {

		case NSCD_DEL_FIRST_DB_ENTRY:
			prev_p = idx_p->prev_p;
			next_p = idx_p->next_p;
			del_more = 0;
			break;

		case NSCD_DEL_EXACT_DB_ENTRY:
			if (db_entry->id_num == id_num) {
				prev_p = idx_p->prev_p;
				next_p = idx_p->next_p;
				del_more = 0;
			} else
				goto cont;
			break;

		case NSCD_DEL_ALL_DB_ENTRY:
			prev_p = idx_p->prev_p;
			next_p = idx_p->next_p;
			break;
		}

		if (prev_p == NULL)
			db->hash_tbl_p[i] = next_p;
		else
			prev_p->next_p = next_p;

		if (next_p != NULL)
			next_p->prev_p = prev_p;

		free(idx_p);

		if (del_more == 0)
			break;
		/*
		 * only when option == NSCD_DEL_ALL_DB_ENTRY
		 * will we get here. next_p should be set to
		 * idx_p->next_p beforehand
		 */
		idx_p = next_p;
		continue;

		cont:

		idx_p = idx_p->next_p;
	}

	return (NSCD_SUCCESS);
}

/*
 * FUNCTION: _nscd_alloc_db_entry
 *
 * Allocate and return the memory for a database entry
 * so the caller can insert data and then add it to the
 * database.
 */
nscd_db_entry_t *
_nscd_alloc_db_entry(
	int			type,
	const char		*name,
	int			dataSize,
	int			num_data,
	int			num_array)
{
	int			size;
	int			array_o, data_o;
	nscd_hash_t		*hash;
	void			*p;

	/* first part: hash data structure and name string */
	size = sizeof (*hash) + strlen(name) + 1;
	array_o = size = roundup(size);

	/* second part: pointer array to data */
	size += (num_data  + num_array) * sizeof (void **);
	size = roundup(size);

	/* third part: actual data */
	data_o = size;
	size += dataSize;

	/* allocate the memory */
	hash = (nscd_hash_t *)calloc(1, size);

	if (hash == NULL)
		return (NULL);

	/* init the entry based on caller's input */
	hash->db_entry.num_data = num_data;
	hash->db_entry.num_array = num_array;
	hash->db_entry.type = type;
	hash->db_entry.name = (char *)hash + sizeof (*hash);
	p = (char *)hash + array_o;
	hash->db_entry.data_array = (void **)p;
	*(hash->db_entry.data_array) = (char *)hash + data_o;
	(void) strcpy(hash->db_entry.name, name);

	return (&hash->db_entry);
}

/*
 * FUNCTION: _nscd_delete_db_entry_cookie
 *
 * Delete a database entry using the information from
 * the input 'cookie'.
 */
void
_nscd_delete_db_entry_cookie(
	nscd_db_t	*db,
	void		**cookie)
{
	nscd_hash_t	*hp;
	struct cookie	*c;

	/* snaity check */
	if (cookie == NULL || *cookie == NULL || db == NULL)
		return;
	c = *cookie;

	/* more snaity check */
	if (db != c->db || c->hash == NULL ||
	    c->idx < 0 || c->idx >= db->array_size)
		return;

	/* retrieve the hash entry from the cookie */
	hp = c->hash;

	/*
	 * Update the next/previous link list.
	 * Need to update c->hash as well, in case
	 * the cookie is also used in a walk-db
	 * loop. This is to make sure that the
	 * next _nscd_walk_db() call will
	 * find the (updated) next hash entry in line.
	 */
	if (hp->prev_p == NULL)	{
		/*
		 * make sure the current bucket will be
		 * walked again if _nscd_walk_db is
		 * called next
		 */
		c->hash = NULL;
		db->hash_tbl_p[c->idx] = hp->next_p;
		c->idx--;

	} else {
		c->hash = hp->prev_p;
		hp->prev_p->next_p = hp->next_p;
	}
	if (hp->next_p != NULL)
		hp->next_p->prev_p = hp->prev_p;

	/* delete the entry */
	free(hp);
}

/*
 * FUNCTION: _nscd_alloc_db
 *
 * Allocate the space for a nscd database.
 *
 * The input argument, size, indicates the size of the database.
 * NSCD_DB_SIZE_LARGE specifies an bucket array of size 67,
 * NSCD_DB_SIZE_MEDIUM specifies an bucket array of size 37,
 * NSCD_DB_SIZE_SMALL specifies an bucket array of size 13,
 * NSCD_DB_SIZE_TINY specifies an bucket array of size 3.
 */
nscd_db_t *
_nscd_alloc_db(
	int		size)
{
	int		sz;
	nscd_db_t	*db;

	/* allocate the database */
	db = (nscd_db_t *)calloc(1, sizeof (nscd_db_t));
	if (db == NULL)
		return (NULL);

	/* allocate the bucket array */
	if (size == NSCD_DB_SIZE_LARGE)
		sz = 67;
	else if (size == NSCD_DB_SIZE_MEDIUM)
		sz = 37;
	else if (size == NSCD_DB_SIZE_SMALL)
		sz = 13;
	else if (size == NSCD_DB_SIZE_TINY)
		sz = 3;
	db->hash_tbl_p = (nscd_hash_t  **)calloc(sz + 1,
	    sizeof (nscd_hash_t *));
	if (db->hash_tbl_p == NULL) {
		free(db);
		return (NULL);
	}

	db->array_size = sz;

	return (db);
}

/*
 * FUNCTION: _nscd_free_db
 *
 * Delete a nscd database.
 */
void
_nscd_free_db(
	nscd_db_t	*db)
{
	int		i;
	nscd_hash_t	*hp, *next_p;

	/*
	 * find non-empty buckets and for each one of them,
	 * delete all the database entries in it's link list
	 */
	for (i = 0; i < db->array_size; i++) {

		hp = db->hash_tbl_p[i];

		while (hp != NULL) {
			next_p = hp->next_p;
			free(hp);
			hp = next_p;
		}
	}

	/* free the bucket array */
	free(db->hash_tbl_p);

	free(db);
}

/*
 * FUNCTION: _nscd_walk_db
 *
 * Iterate through the database entries contained in
 * a nscd database and return one entry at a time.
 * The cookie structure is used to indicate the
 * location of the returned entry for the next call
 * to this function. For the very first call, *cookie
 * should be set to NULL. For subsequent calls, the one
 * returned by the previous call sould be used.
 */
nscd_db_entry_t *
_nscd_walk_db(
	nscd_db_t	*db,
	void		**cookie)
{
	struct cookie	*c;

	/* sanity check */
	if (cookie == NULL || db == NULL)
		return (NULL);

	if (*cookie != NULL) {

		c = *cookie;

		/*
		 * More sanity check. _nscd_delete_db_entry_cookie()
		 * could change c->idx to -1.
		 */
		if (db != c->db ||
		    c->idx < -1 || c->idx >= db->array_size)
			return (NULL);

		/* is there a next entry ? */
		if (c->hash != NULL)
			c->hash = c->hash->next_p;

		/* yes, return it */
		if (c->hash != NULL) {
			return (&c->hash->db_entry);
		}
	} else {
		c = (struct cookie *)calloc(1, sizeof (*c));
		if (c == NULL)
			return (NULL);
		c->idx = -1;
		c->hash = NULL;
		c->db = db;
	}

	/* find the first non-empty bucket */
	for (c->idx++; c->idx < db->array_size; c->idx++) {
		c->hash = db->hash_tbl_p[c->idx];
		if (c->hash != NULL)
			break;
	}

	/* no (more) non-empty bucket, we are done */
	if (c->hash == NULL) {
		free(c);
		*cookie = NULL;
		return (NULL);
	}

	*cookie = c;
	return (&c->hash->db_entry);
}
