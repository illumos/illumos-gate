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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * dict.c - simple dictionary facility
 *
 * We maintain a dictionary, sorted by name to facilitate rapid id lookup by
 * name. It is used by both the restarter and graph code.
 *
 * Right now, the dictionary is implemented as a sorted linked list which maps
 * instance names to graph vertex ids.  It should eventually be converted to a
 * better representation for quick lookups.
 *
 * For now, FMRIs are never deleted from the dictionary. A service deletion
 * and insertion of the same instance FMRI will result in reuse of the same
 * id. To implement dictionary entry delete, the locking strategy for graph
 * vertex dependency linking must be checked for accuracy, as assumptions may
 * exist that FMRI to id mapping is retained even after an instance is deleted.
 */

#include <sys/time.h>

#include <assert.h>
#include <libuutil.h>
#include <string.h>

#include "startd.h"

static uu_list_pool_t *dict_pool;
dictionary_t *dictionary;

static u_longlong_t dictionary_lookups;		/* number of lookups */
static u_longlong_t dictionary_ns_total;	/* nanoseconds spent */

/*ARGSUSED*/
static int
dict_compare(const void *lc_arg, const void *rc_arg, void *private)
{
	const char *lc_name = ((const dict_entry_t *)lc_arg)->de_name;
	const char *rc_name = ((const dict_entry_t *)rc_arg)->de_name;

	return (strcmp(lc_name, rc_name));
}

int
dict_lookup_byname(const char *name)
{
	int id;
	dict_entry_t *entry, tmp;
	hrtime_t now = gethrtime();

	tmp.de_name = name;

	(void) pthread_mutex_lock(&dictionary->dict_lock);
	if ((entry = uu_list_find(dictionary->dict_list, &tmp, NULL,
	    NULL)) == NULL)
		id = -1;
	else
		id = entry->de_id;

	(void) pthread_mutex_unlock(&dictionary->dict_lock);

	dictionary_lookups++;
	dictionary_ns_total += gethrtime() - now;

	return (id);
}

/*
 * int dict_insert(char *)
 *   Returns the ID for name.
 */
int
dict_insert(const char *name)
{
	dict_entry_t *entry, tmp;
	uu_list_index_t idx;

	assert(name != NULL);

	tmp.de_name = name;

	(void) pthread_mutex_lock(&dictionary->dict_lock);

	if ((entry = uu_list_find(dictionary->dict_list, &tmp, NULL,
	    &idx)) != NULL) {
		(void) pthread_mutex_unlock(&dictionary->dict_lock);
		return (entry->de_id);
	}

	entry = startd_alloc(sizeof (dict_entry_t));

	entry->de_id = dictionary->dict_new_id++;
	entry->de_name = startd_alloc(strlen(name) + 1);
	(void) strcpy((char *)entry->de_name, name);

	uu_list_node_init(entry, &entry->de_link, dict_pool);

	uu_list_insert(dictionary->dict_list, entry, idx);
	(void) pthread_mutex_unlock(&dictionary->dict_lock);

	return (entry->de_id);
}

void
dict_init()
{
	dictionary = startd_zalloc(sizeof (dictionary_t));

	(void) pthread_mutex_init(&dictionary->dict_lock, NULL);

	dict_pool = startd_list_pool_create("dict", sizeof (dict_entry_t),
	    offsetof(dict_entry_t, de_link), dict_compare, UU_LIST_POOL_DEBUG);
	assert(dict_pool != NULL);

	dictionary->dict_new_id = 0;
	dictionary->dict_list = startd_list_create(dict_pool, dictionary,
	    UU_LIST_SORTED);
	assert(dictionary->dict_list != NULL);
}
