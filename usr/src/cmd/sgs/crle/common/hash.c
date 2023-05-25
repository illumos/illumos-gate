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
 * Copyright (c) 2000 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#include	<stdio.h>
#include	<stdlib.h>
#include	<string.h>
#include	<libelf.h>
#include	"_crle.h"

Hash_tbl *
make_hash(int size, Hash_type type, ulong_t ident)
{
	Hash_tbl *	tbl;

	if ((tbl = malloc(sizeof (Hash_tbl))) == 0)
		return (0);

	tbl->t_entry = calloc(size, (unsigned)(sizeof (Hash_ent *)));
	if (tbl->t_entry == NULL) {
		free(tbl);
		return (0);
	}

	tbl->t_ident = ident;
	tbl->t_type = type;
	tbl->t_size = size;

	return (tbl);
}


Hash_ent *
get_hash(Hash_tbl * tbl, Addr key, Half id, int mode)
{
	int		bucket;
	Hash_ent *	ent;
	Word		hashval;

	if (tbl->t_type == HASH_STR)
		hashval = elf_hash((const char *)key);
	else
		hashval = key;

	bucket = hashval % tbl->t_size;

	if (mode & HASH_FND_ENT) {
		for (ent = tbl->t_entry[bucket]; ent != NULL;
		    ent = ent->e_next) {
			if (tbl->t_type == HASH_STR) {
				if ((strcmp((const char *)ent->e_key,
				    (const char *)key) == 0) && ((id == 0) ||
				    (id == ent->e_id)))
					return (ent);
			} else {
				if (ent->e_key == key)
					return (ent);
			}
		}
	}
	if (!(mode & HASH_ADD_ENT))
		return (0);

	/*
	 * Key not found in this hash table ... insert new entry into bucket.
	 */
	if ((ent = calloc(1, sizeof (Hash_ent))) == NULL)
		return (0);

	ent->e_key = key;
	ent->e_hash = hashval;

	/*
	 * Hook into bucket chain
	 */
	ent->e_next = tbl->t_entry[bucket];
	tbl->t_entry[bucket] = ent;

	return (ent);
}
