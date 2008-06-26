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

#define	CACHE_TRIGGER_SIZE	4096
#define	CACHE_PURGE_INTERVAL	(60 * 3)
#define	CACHE_TTL		(60 * 10)

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
	int64_t comp = ((int64_t)entry2->rid) - ((int64_t)entry1->rid);

	if (comp == 0)
		comp = strcmp(entry2->sid_prefix, entry1->sid_prefix);

	if (comp < 0)
		comp = -1;
	else if (comp > 0)
		comp = 1;

	return ((int)comp);
}


static int
kidmap_compare_pid(const entry_t *entry1, const entry_t *entry2)
{
	if (entry2->pid > entry1->pid)
		return (1);
	if (entry2->pid < entry1->pid)
		return (-1);
	return (0);
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
	avl_create(&cache->uidbysid.tree, (avl_comp_fn)kidmap_compare_sid,
	    sizeof (entry_t), offsetof(entry_t, avl_link));
	mutex_init(&cache->uidbysid.mutex, NULL, MUTEX_DEFAULT, NULL);
	cache->uidbysid.purge_time = 0;

	avl_create(&cache->gidbysid.tree, (avl_comp_fn)kidmap_compare_sid,
	    sizeof (entry_t), offsetof(entry_t, avl_link));
	mutex_init(&cache->gidbysid.mutex, NULL, MUTEX_DEFAULT, NULL);
	cache->gidbysid.purge_time = 0;

	avl_create(&cache->pidbysid.tree, (avl_comp_fn)kidmap_compare_sid,
	    sizeof (entry_t), offsetof(entry_t, avl_link));
	mutex_init(&cache->pidbysid.mutex, NULL, MUTEX_DEFAULT, NULL);
	cache->pidbysid.purge_time = 0;

	avl_create(&cache->sidbyuid.tree, (avl_comp_fn)kidmap_compare_pid,
	    sizeof (entry_t), offsetof(entry_t, avl_link));
	mutex_init(&cache->sidbyuid.mutex, NULL, MUTEX_DEFAULT, NULL);
	cache->sidbyuid.purge_time = 0;

	avl_create(&cache->sidbygid.tree, (avl_comp_fn)kidmap_compare_pid,
	    sizeof (entry_t), offsetof(entry_t, avl_link));
	mutex_init(&cache->sidbygid.mutex, NULL, MUTEX_DEFAULT, NULL);
	cache->sidbygid.purge_time = 0;
}


void
kidmap_cache_delete(idmap_cache_t *cache)
{
	entry_t *entry;
	void *cookie;

	cookie = NULL;
	while ((entry = avl_destroy_nodes(&cache->uidbysid.tree, &cookie))
	    != NULL) {
		kmem_free(entry, sizeof (entry_t));
	}
	avl_destroy(&cache->uidbysid.tree);
	mutex_destroy(&cache->uidbysid.mutex);

	cookie = NULL;
	while ((entry = avl_destroy_nodes(&cache->gidbysid.tree, &cookie))
	    != NULL) {
		kmem_free(entry, sizeof (entry_t));
	}
	avl_destroy(&cache->gidbysid.tree);
	mutex_destroy(&cache->gidbysid.mutex);

	cookie = NULL;
	while ((entry = avl_destroy_nodes(&cache->pidbysid.tree, &cookie))
	    != NULL) {
		kmem_free(entry, sizeof (entry_t));
	}
	avl_destroy(&cache->pidbysid.tree);
	mutex_destroy(&cache->pidbysid.mutex);

	cookie = NULL;
	while ((entry = avl_destroy_nodes(&cache->sidbyuid.tree, &cookie))
	    != NULL) {
		kmem_free(entry, sizeof (entry_t));
	}
	avl_destroy(&cache->sidbyuid.tree);
	mutex_destroy(&cache->sidbyuid.mutex);

	cookie = NULL;
	while ((entry = avl_destroy_nodes(&cache->sidbygid.tree, &cookie))
	    != NULL) {
		kmem_free(entry, sizeof (entry_t));
	}
	avl_destroy(&cache->sidbygid.tree);
	mutex_destroy(&cache->sidbygid.mutex);
}


void
kidmap_cache_get_data(idmap_cache_t *cache, size_t *uidbysid, size_t *gidbysid,
	size_t *pidbysid, size_t *sidbyuid, size_t *sidbygid)
{
	mutex_enter(&cache->uidbysid.mutex);
	*uidbysid = avl_numnodes(&cache->uidbysid.tree);
	mutex_exit(&cache->uidbysid.mutex);

	mutex_enter(&cache->gidbysid.mutex);
	*gidbysid = avl_numnodes(&cache->gidbysid.tree);
	mutex_exit(&cache->gidbysid.mutex);

	mutex_enter(&cache->pidbysid.mutex);
	*pidbysid = avl_numnodes(&cache->pidbysid.tree);
	mutex_exit(&cache->pidbysid.mutex);

	mutex_enter(&cache->sidbyuid.mutex);
	*sidbyuid = avl_numnodes(&cache->sidbyuid.tree);
	mutex_exit(&cache->sidbyuid.mutex);

	mutex_enter(&cache->sidbygid.mutex);
	*sidbygid = avl_numnodes(&cache->sidbygid.tree);
	mutex_exit(&cache->sidbygid.mutex);
}


void
kidmap_cache_purge(idmap_cache_t *cache)
{
	entry_t *entry;
	void *cookie;

	mutex_enter(&cache->uidbysid.mutex);
	cookie = NULL;
	while ((entry = avl_destroy_nodes(&cache->uidbysid.tree, &cookie))
	    != NULL) {
		kmem_free(entry, sizeof (entry_t));
	}
	avl_destroy(&cache->uidbysid.tree);
	avl_create(&cache->uidbysid.tree, (avl_comp_fn)kidmap_compare_sid,
	    sizeof (entry_t), offsetof(entry_t, avl_link));
	mutex_exit(&cache->uidbysid.mutex);

	mutex_enter(&cache->gidbysid.mutex);
	cookie = NULL;
	while ((entry = avl_destroy_nodes(&cache->gidbysid.tree, &cookie))
	    != NULL) {
		kmem_free(entry, sizeof (entry_t));
	}
	avl_destroy(&cache->gidbysid.tree);
	avl_create(&cache->gidbysid.tree, (avl_comp_fn)kidmap_compare_sid,
	    sizeof (entry_t), offsetof(entry_t, avl_link));
	mutex_exit(&cache->gidbysid.mutex);

	mutex_enter(&cache->pidbysid.mutex);
	cookie = NULL;
	while ((entry = avl_destroy_nodes(&cache->pidbysid.tree, &cookie))
	    != NULL) {
		kmem_free(entry, sizeof (entry_t));
	}
	avl_destroy(&cache->pidbysid.tree);
	avl_create(&cache->pidbysid.tree, (avl_comp_fn)kidmap_compare_sid,
	    sizeof (entry_t), offsetof(entry_t, avl_link));
	mutex_exit(&cache->pidbysid.mutex);

	mutex_enter(&cache->sidbyuid.mutex);
	cookie = NULL;
	while ((entry = avl_destroy_nodes(&cache->sidbyuid.tree, &cookie))
	    != NULL) {
		kmem_free(entry, sizeof (entry_t));
	}
	avl_destroy(&cache->sidbyuid.tree);
	avl_create(&cache->sidbyuid.tree, (avl_comp_fn)kidmap_compare_pid,
	    sizeof (entry_t), offsetof(entry_t, avl_link));
	mutex_exit(&cache->sidbyuid.mutex);

	mutex_enter(&cache->sidbygid.mutex);
	cookie = NULL;
	while ((entry = avl_destroy_nodes(&cache->sidbygid.tree, &cookie))
	    != NULL) {
		kmem_free(entry, sizeof (entry_t));
	}
	avl_destroy(&cache->sidbygid.tree);
	avl_create(&cache->sidbygid.tree, (avl_comp_fn)kidmap_compare_pid,
	    sizeof (entry_t), offsetof(entry_t, avl_link));
	mutex_exit(&cache->sidbygid.mutex);
}


int
kidmap_cache_lookup_uidbysid(idmap_cache_t *cache, const char *sid_prefix,
			uint32_t rid, uid_t *uid)
{
	entry_t		entry;
	entry_t		*result;
	avl_index_t	where;
	int		status;
	time_t		now = gethrestime_sec();

	entry.sid_prefix = sid_prefix;
	entry.rid = rid;

	mutex_enter(&cache->uidbysid.mutex);

	result = avl_find(&cache->uidbysid.tree, &entry, &where);

	if (result && result->ttl > now) {
		*uid = result->pid;
		status = IDMAP_SUCCESS;
	} else
		status = IDMAP_ERR_NOMAPPING;

	mutex_exit(&cache->uidbysid.mutex);

	return (status);
}



int
kidmap_cache_lookup_gidbysid(idmap_cache_t *cache, const char *sid_prefix,
			uint32_t rid, gid_t *gid)
{
	entry_t		entry;
	entry_t		*result;
	avl_index_t	where;
	int		status;
	time_t		now = gethrestime_sec();

	entry.sid_prefix = sid_prefix;
	entry.rid = rid;

	mutex_enter(&cache->gidbysid.mutex);

	result = avl_find(&cache->gidbysid.tree, &entry, &where);

	if (result && result->ttl > now) {
		*gid = result->pid;
		status = IDMAP_SUCCESS;
	} else
		status = IDMAP_ERR_NOMAPPING;

	mutex_exit(&cache->gidbysid.mutex);

	return (status);
}




int
kidmap_cache_lookup_pidbysid(idmap_cache_t *cache, const char *sid_prefix,
			uint32_t rid, uid_t *pid, int *is_user)
{
	entry_t		entry;
	entry_t		*result;
	avl_index_t	where;
	int		status;
	time_t		now = gethrestime_sec();

	entry.sid_prefix = sid_prefix;
	entry.rid = rid;

	mutex_enter(&cache->pidbysid.mutex);

	result = avl_find(&cache->pidbysid.tree, &entry, &where);

	if (result && result->ttl > now) {
		*pid = result->pid;
		*is_user = result->is_user;
		status = IDMAP_SUCCESS;
	} else
		status = IDMAP_ERR_NOMAPPING;

	mutex_exit(&cache->pidbysid.mutex);

	return (status);
}



int
kidmap_cache_lookup_sidbyuid(idmap_cache_t *cache, const char **sid_prefix,
			uint32_t *rid, uid_t uid)
{
	entry_t		entry;
	entry_t		*result;
	avl_index_t	where;
	int		status;
	time_t		now = gethrestime_sec();

	entry.pid = uid;

	mutex_enter(&cache->sidbyuid.mutex);

	result = avl_find(&cache->sidbyuid.tree, &entry, &where);

	if (result && result->ttl > now) {
		*sid_prefix = result->sid_prefix;
		*rid = result->rid;
		status = IDMAP_SUCCESS;
	} else
		status = IDMAP_ERR_NOMAPPING;

	mutex_exit(&cache->sidbyuid.mutex);

	return (status);
}

int
kidmap_cache_lookup_sidbygid(idmap_cache_t *cache, const char **sid_prefix,
			uint32_t *rid, gid_t gid)
{
	entry_t		entry;
	entry_t		*result;
	avl_index_t	where;
	int		status;
	time_t		now = gethrestime_sec();

	entry.pid = gid;

	mutex_enter(&cache->sidbygid.mutex);

	result = avl_find(&cache->sidbygid.tree, &entry, &where);

	if (result && result->ttl > now) {
		*sid_prefix = result->sid_prefix;
		*rid = result->rid;
		status = IDMAP_SUCCESS;
	} else
		status = IDMAP_ERR_NOMAPPING;

	mutex_exit(&cache->sidbygid.mutex);

	return (status);
}




void
kidmap_cache_add_uidbysid(idmap_cache_t *cache, const char *sid_prefix,
			uint32_t rid, uid_t uid)

{
	entry_t		find;
	entry_t		*result;
	entry_t		*new;
	avl_index_t	where;
	int		purge_required = FALSE;
	time_t		ttl = CACHE_TTL + gethrestime_sec();

	find.sid_prefix = sid_prefix;
	find.rid = rid;

	mutex_enter(&cache->uidbysid.mutex);
	result = avl_find(&cache->uidbysid.tree, &find, &where);

	if (result) {
		result->pid = uid;
		result->ttl = ttl;
	} else {
		new = kmem_alloc(sizeof (entry_t), KM_SLEEP);
		new->pid = uid;
		new->sid_prefix = sid_prefix;
		new->rid = rid;
		new->ttl = ttl;

		avl_insert(&cache->uidbysid.tree, new, where);

		if ((avl_numnodes(&cache->uidbysid.tree) >
		    CACHE_TRIGGER_SIZE) &&
		    (cache->uidbysid.purge_time + CACHE_PURGE_INTERVAL <
		    gethrestime_sec()))
			purge_required = TRUE;
	}

	mutex_exit(&cache->uidbysid.mutex);

	if (purge_required)
		kidmap_cache_purge_avl(&cache->uidbysid);
}


void
kidmap_cache_add_gidbysid(idmap_cache_t *cache, const char *sid_prefix,
			uint32_t rid, gid_t gid)

{
	entry_t		find;
	entry_t		*result;
	entry_t		*new;
	avl_index_t	where;
	int		purge_required = FALSE;
	time_t		ttl = CACHE_TTL + gethrestime_sec();

	find.sid_prefix = sid_prefix;
	find.rid = rid;

	mutex_enter(&cache->gidbysid.mutex);
	result = avl_find(&cache->gidbysid.tree, &find, &where);

	if (result) {
		result->pid = gid;
		result->ttl = ttl;
	} else {
		new = kmem_alloc(sizeof (entry_t), KM_SLEEP);
		new->pid = gid;
		new->sid_prefix = sid_prefix;
		new->rid = rid;
		new->ttl = ttl;

		avl_insert(&cache->gidbysid.tree, new, where);

		if ((avl_numnodes(&cache->gidbysid.tree) >
		    CACHE_TRIGGER_SIZE) &&
		    (cache->gidbysid.purge_time + CACHE_PURGE_INTERVAL <
		    gethrestime_sec()))
			purge_required = TRUE;
	}

	mutex_exit(&cache->gidbysid.mutex);

	if (purge_required)
		kidmap_cache_purge_avl(&cache->gidbysid);
}

void
kidmap_cache_add_pidbysid(idmap_cache_t *cache, const char *sid_prefix,
			uint32_t rid, uid_t pid, int is_user)

{
	entry_t		find;
	entry_t		*result;
	entry_t		*new;
	avl_index_t	where;
	int		purge_required = FALSE;
	time_t		ttl = CACHE_TTL + gethrestime_sec();

	find.sid_prefix = sid_prefix;
	find.rid = rid;

	mutex_enter(&cache->pidbysid.mutex);
	result = avl_find(&cache->pidbysid.tree, &find, &where);

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

		avl_insert(&cache->pidbysid.tree, new, where);

		if ((avl_numnodes(&cache->pidbysid.tree) >
		    CACHE_TRIGGER_SIZE) &&
		    (cache->pidbysid.purge_time + CACHE_PURGE_INTERVAL <
		    gethrestime_sec()))
			purge_required = TRUE;
	}

	mutex_exit(&cache->pidbysid.mutex);

	if (purge_required)
		kidmap_cache_purge_avl(&cache->pidbysid);
}



void
kidmap_cache_add_sidbyuid(idmap_cache_t *cache, const char *sid_prefix,
			uint32_t rid, uid_t uid)
{
	entry_t		find;
	entry_t		*result;
	entry_t		*new;
	avl_index_t	where;
	int		purge_required = FALSE;
	time_t		ttl = CACHE_TTL + gethrestime_sec();

	find.pid = uid;

	mutex_enter(&cache->sidbyuid.mutex);
	result = avl_find(&cache->sidbyuid.tree, &find, &where);

	if (result) {
		result->sid_prefix = sid_prefix;
		result->rid = rid;
		result->ttl = ttl;
	} else {
		new = kmem_alloc(sizeof (entry_t), KM_SLEEP);
		new->pid = uid;
		new->sid_prefix = sid_prefix;
		new->rid = rid;
		new->ttl = ttl;

		avl_insert(&cache->sidbyuid.tree, new, where);
		if ((avl_numnodes(&cache->sidbyuid.tree) >
		    CACHE_TRIGGER_SIZE) &&
		    (cache->sidbyuid.purge_time + CACHE_PURGE_INTERVAL <
		    gethrestime_sec()))
			purge_required = TRUE;
	}

	mutex_exit(&cache->sidbyuid.mutex);

	if (purge_required)
		kidmap_cache_purge_avl(&cache->sidbyuid);
}


void
kidmap_cache_add_sidbygid(idmap_cache_t *cache, const char *sid_prefix,
			uint32_t rid, gid_t gid)
{
	entry_t		find;
	entry_t		*result;
	entry_t		*new;
	avl_index_t	where;
	int		purge_required = FALSE;
	time_t		ttl = CACHE_TTL + gethrestime_sec();

	find.pid = gid;

	mutex_enter(&cache->sidbygid.mutex);
	result = avl_find(&cache->sidbygid.tree, &find, &where);

	if (result) {
		result->sid_prefix = sid_prefix;
		result->rid = rid;
		result->ttl = ttl;
	} else {
		new = kmem_alloc(sizeof (entry_t), KM_SLEEP);
		new->pid = gid;
		new->sid_prefix = sid_prefix;
		new->rid = rid;
		new->ttl = ttl;

		avl_insert(&cache->sidbygid.tree, new, where);
		if ((avl_numnodes(&cache->sidbygid.tree) >
		    CACHE_TRIGGER_SIZE) &&
		    (cache->sidbygid.purge_time + CACHE_PURGE_INTERVAL <
		    gethrestime_sec()))
			purge_required = TRUE;
	}

	mutex_exit(&cache->sidbygid.mutex);

	if (purge_required)
		kidmap_cache_purge_avl(&cache->sidbygid);
}


static void
kidmap_cache_purge_avl(idmap_avl_cache_t *cache)
{
	time_t		now = gethrestime_sec();
	entry_t		*curr;
	entry_t		*prev = NULL;

	mutex_enter(&cache->mutex);

	curr = avl_first(&cache->tree);
	while (curr != NULL) {
		if (curr->ttl < now) {
			/* Old entry to remove */
			avl_remove(&cache->tree, curr);
			kmem_free(curr, sizeof (entry_t));
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
		 * and acquire the write lock
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
