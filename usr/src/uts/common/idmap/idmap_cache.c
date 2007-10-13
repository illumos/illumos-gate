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

/*
 * Windows to Solaris Identity Mapping kernel API
 * This module provides the kernel cache.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"


#include <sys/types.h>
#include <sys/avl.h>
#include <sys/systm.h>
#include <sys/sysmacros.h>
#include <sys/ksynch.h>
#include <sys/kidmap.h>
#include "idmap_prot.h"
#include "kidmap_priv.h"


/*
 * External functions
 */
extern	uintptr_t	space_fetch(char *key);
extern	int		space_store(char *key, uintptr_t ptr);


/*
 * Internal definitions and functions
 */

#define	CACHE_TRIGGER_SIZE	8192
#define	CACHE_PURGE_INTERVAL	(60 * 3)

typedef struct sid_prefix_node {
	avl_node_t	avl_link;
	const char 	*sid_prefix;
} sid_prefix_node_t;


typedef struct entry {
	avl_node_t	avl_link;
	const char 	*sid_prefix;
	uint32_t	rid;
	uid_t		pid;
	int		is_user;
	time_t		ttl;
} entry_t;

typedef int (*avl_comp_fn)(const void*, const void*);


struct sid_prefix_store {
	struct avl_tree	tree;
	krwlock_t	lock;
};

struct sid_prefix_store *kidmap_sid_prefix_store = NULL;



static void
kidmap_cache_purge_avl(idmap_avl_cache_t *cache);

/*
 * kidmap_strdup() copied from uts/common/fs/sockfs/nl7c.c
 */
static char *
kidmap_strdup(const char *s)
{
	int	len = strlen(s) + 1;
	char	*ret = kmem_alloc(len, KM_SLEEP);

	bcopy(s, ret, len);
	return (ret);
}


static int
kidmap_compare_sid(const entry_t *entry1, const entry_t *entry2)
{
	int comp = entry2->rid - entry1->rid;

	if (comp == 0)
		comp = strcmp(entry2->sid_prefix, entry1->sid_prefix);

	if (comp < 0)
		comp = -1;
	else if (comp > 0)
		comp = 1;

	return (comp);
}


static int
kidmap_compare_pid(const entry_t *entry1, const entry_t *entry2)
{
	int comp = entry2->pid - entry1->pid;

	if (comp == 0)
		comp = entry2->is_user - entry1->is_user;

	if (comp < 0)
		comp = -1;
	else if (comp > 0)
		comp = 1;

	return (comp);
}


static int
kidmap_compare_sid_prefix(const sid_prefix_node_t *entry1,
			const sid_prefix_node_t *entry2)
{
	int comp;

	comp = strcmp(entry2->sid_prefix, entry1->sid_prefix);

	if (comp < 0)
		comp = -1;
	else if (comp > 0)
		comp = 1;

	return (comp);
}


void
kidmap_cache_create(idmap_cache_t *cache)
{
	typedef int (*comp)(const void*, const void*);

	rw_init(&cache->sid.lock, NULL, RW_DRIVER, NULL);
	avl_create(&cache->sid.tree, (avl_comp_fn)kidmap_compare_sid,
	    sizeof (entry_t), offsetof(entry_t, avl_link));
	mutex_init(&cache->sid.mutex, NULL, MUTEX_DEFAULT, NULL);
	cache->sid.state = CACHE_CREATED;
	cache->sid.purge_time = 0;

	rw_init(&cache->pid.lock, NULL, RW_DRIVER, NULL);
	avl_create(&cache->pid.tree, (avl_comp_fn)kidmap_compare_pid,
	    sizeof (entry_t), offsetof(entry_t, avl_link));
	mutex_init(&cache->pid.mutex, NULL, MUTEX_DEFAULT, NULL);
	cache->pid.state = CACHE_CREATED;
	cache->pid.purge_time = 0;
}


void
kidmap_cache_delete(idmap_cache_t *cache)
{
	entry_t *entry;
	void *cookie;

	cookie = NULL;
	while ((entry = avl_destroy_nodes(&cache->pid.tree, &cookie))
	    != NULL) {
		kmem_free(entry, sizeof (entry_t));
	}
	avl_destroy(&cache->pid.tree);
	rw_destroy(&cache->pid.lock);
	mutex_destroy(&cache->pid.mutex);

	cookie = NULL;
	while ((entry = avl_destroy_nodes(&cache->sid.tree, &cookie))
	    != NULL) {
		kmem_free(entry, sizeof (entry_t));
	}
	avl_destroy(&cache->sid.tree);
	rw_destroy(&cache->sid.lock);
	mutex_destroy(&cache->sid.mutex);
}


int
kidmap_cache_lookupbypid(idmap_cache_t *cache, const char **sid_prefix,
			uint32_t *rid, uid_t pid, int is_user)

{
	entry_t		entry;
	entry_t		*result;
	avl_index_t	where;
	int		status;
	time_t		now = gethrestime_sec();

	entry.pid = pid;
	entry.is_user = is_user;

	rw_enter(&cache->pid.lock, RW_READER);

	result = avl_find(&cache->pid.tree, &entry, &where);

	if (result && result->ttl > now) {
		*sid_prefix = result->sid_prefix;
		*rid = result->rid;
		status = IDMAP_SUCCESS;
	} else
		status = IDMAP_ERR_NOMAPPING;

	rw_exit(&cache->pid.lock);

	return (status);
}


int
kidmap_cache_lookupbysid(idmap_cache_t *cache, const char *sid_prefix,
			uint32_t rid, uid_t *pid, int *is_user)
{
	entry_t		entry;
	entry_t		*result;
	avl_index_t	where;
	int		status;
	time_t		now = gethrestime_sec();

	entry.sid_prefix = sid_prefix;
	entry.rid = rid;

	rw_enter(&cache->sid.lock, RW_READER);

	result = avl_find(&cache->sid.tree, &entry, &where);

	if (result && result->ttl > now) {
		*pid = result->pid;
		*is_user = result->is_user;
		status = IDMAP_SUCCESS;
	} else
		status = IDMAP_ERR_NOMAPPING;

	rw_exit(&cache->sid.lock);

	return (status);
}


void
kidmap_cache_addbypid(idmap_cache_t *cache, const char *sid_prefix,
			uint32_t rid, uid_t pid, int is_user, time_t ttl)
{
	entry_t		find;
	entry_t		*result;
	entry_t		*new;
	avl_index_t	where;
	int		purge_required = FALSE;

	find.pid = pid;
	find.is_user = is_user;

	rw_enter(&cache->pid.lock, RW_WRITER);
	result = avl_find(&cache->pid.tree, &find, &where);

	if (result) {
		result->sid_prefix = sid_prefix;
		result->rid = rid;
		result->ttl = ttl;
	} else {
		new = kmem_alloc(sizeof (entry_t), KM_SLEEP);
		new->pid = pid;
		new->is_user = is_user;
		new->sid_prefix = sid_prefix;
		new->rid = rid;
		new->ttl = ttl;

		avl_insert(&cache->pid.tree, new, where);
		if ((avl_numnodes(&cache->pid.tree) > CACHE_TRIGGER_SIZE) &&
		    (cache->pid.purge_time + CACHE_PURGE_INTERVAL <
		    gethrestime_sec()))
			purge_required = TRUE;
	}

	rw_exit(&cache->pid.lock);

	if (purge_required)
		kidmap_cache_purge_avl(&cache->pid);
}


void
kidmap_cache_addbysid(idmap_cache_t *cache, const char *sid_prefix,
			uint32_t rid, uid_t pid, int is_user, time_t ttl)

{
	entry_t find;
	entry_t *result;
	entry_t *new;
	avl_index_t where;
	int purge_required = FALSE;

	find.sid_prefix = sid_prefix;
	find.rid = rid;

	rw_enter(&cache->sid.lock, RW_WRITER);
	result = avl_find(&cache->sid.tree, &find, &where);

	if (result) {
		result->pid = pid;
		result->is_user = is_user;
		result->ttl = ttl;
	} else {
		new = kmem_alloc(sizeof (entry_t), KM_SLEEP);
		new->pid = pid;
		new->is_user = is_user;
		new->sid_prefix = sid_prefix;
		new->rid = rid;
		new->ttl = ttl;

		avl_insert(&cache->sid.tree, new, where);

		if ((avl_numnodes(&cache->sid.tree) > CACHE_TRIGGER_SIZE) &&
		    (cache->sid.purge_time + CACHE_PURGE_INTERVAL <
		    gethrestime_sec()))
			purge_required = TRUE;
	}

	rw_exit(&cache->sid.lock);

	if (purge_required)
		kidmap_cache_purge_avl(&cache->sid);
}


static void
kidmap_cache_purge_avl(idmap_avl_cache_t *cache)
{
	time_t		now = gethrestime_sec();
	entry_t		*curr;
	entry_t		*prev = NULL;

	mutex_enter(&cache->mutex);
	if (cache->state != CACHE_CREATED) {
			mutex_exit(&cache->mutex);
			return;
	}
	cache->state = CACHE_PURGING;
	mutex_exit(&cache->mutex);

	rw_enter(&cache->lock, RW_READER);
	curr = avl_first(&cache->tree);
	while (curr != NULL) {
		if (curr->ttl < now) {
			/* Old entry to remove - we need a write lock */
			if (rw_tryupgrade(&cache->lock) == 0) {
				/*
				 * Could not upgrade lock so release lock
				 * and aquire the write lock. It is valid to
				 * release abd re-aquire the lock as there
				 * can only be one purge routine running on an
				 * avl tree and no other routine removes
				 * entries.
				 */
				rw_exit(&cache->lock);
				rw_enter(&cache->lock, RW_WRITER);
			}
			/* Old entry to remove */
			avl_remove(&cache->tree, curr);
			rw_downgrade(&cache->lock);

			curr = prev;
			if (curr == NULL) {
				/* We removed the first entery */
				curr = avl_first(&cache->tree);
				continue;
			}
		}
		prev = curr;
		curr = AVL_NEXT(&cache->tree, curr);
	}
	rw_exit(&cache->lock);

	mutex_enter(&cache->mutex);
	cache->state = CACHE_CREATED;
	cache->purge_time = now;
	mutex_exit(&cache->mutex);
}

void
kidmap_sid_prefix_store_init(void)
{
	kidmap_sid_prefix_store = (struct sid_prefix_store *)
	    space_fetch("SUNW,idmap_sid_prefix");
	if (kidmap_sid_prefix_store == NULL) {
		kidmap_sid_prefix_store = kmem_alloc(
		    sizeof (struct sid_prefix_store), KM_SLEEP);
		rw_init(&kidmap_sid_prefix_store->lock, NULL, RW_DRIVER, NULL);
		avl_create(&kidmap_sid_prefix_store->tree,
		    (avl_comp_fn)kidmap_compare_sid_prefix,
		    sizeof (sid_prefix_node_t),
		    offsetof(sid_prefix_node_t, avl_link));
		(void) space_store("SUNW,idmap_sid_prefix",
		    (uintptr_t)kidmap_sid_prefix_store);
	} else {
		/*
		 * The AVL comparison function must be re-initialised on
		 * re-load because may not be loaded into the same
		 * address space.
		 */
		kidmap_sid_prefix_store->tree.avl_compar =
		    (avl_comp_fn)kidmap_compare_sid_prefix;
	}
}


const char *
kidmap_find_sid_prefix(const char *sid_prefix) {
	sid_prefix_node_t 	find;
	sid_prefix_node_t	*result;
	sid_prefix_node_t 	*new;
	avl_index_t		where;

	if (sid_prefix == NULL || *sid_prefix == '\0')
		return (NULL);

	find.sid_prefix = sid_prefix;


	rw_enter(&kidmap_sid_prefix_store->lock, RW_READER);

	result = avl_find(&kidmap_sid_prefix_store->tree, &find, &where);

	if (result) {
		rw_exit(&kidmap_sid_prefix_store->lock);
		return (result->sid_prefix);
	}

	if (rw_tryupgrade(&kidmap_sid_prefix_store->lock) == 0) {
		/*
		 * Could not upgrade lock so release lock
		 * and aquire the write lock
		 */
		rw_exit(&kidmap_sid_prefix_store->lock);
		rw_enter(&kidmap_sid_prefix_store->lock, RW_WRITER);

		result = avl_find(&kidmap_sid_prefix_store->tree,
			&find, &where);
		if (result) {
			rw_exit(&kidmap_sid_prefix_store->lock);
			return (result->sid_prefix);
		}
	}

	new = kmem_alloc(sizeof (sid_prefix_node_t), KM_SLEEP);
	new->sid_prefix = kidmap_strdup(sid_prefix);
	avl_insert(&kidmap_sid_prefix_store->tree, new, where);
	rw_exit(&kidmap_sid_prefix_store->lock);

	return (new->sid_prefix);
}
