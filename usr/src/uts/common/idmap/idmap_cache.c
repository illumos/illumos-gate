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

#define	CACHE_UID_TRIGGER_SIZE	4096
#define	CACHE_GID_TRIGGER_SIZE	2048
#define	CACHE_PID_TRIGGER_SIZE \
	(CACHE_UID_TRIGGER_SIZE + CACHE_GID_TRIGGER_SIZE)


#define	UNDEF_UID	((uid_t)-1)
#define	UNDEF_GID	((gid_t)-1)
#define	UNDEF_ISUSER	(-1)

#define	CACHE_PURGE_INTERVAL	(60 * 3)
#define	CACHE_TTL		(60 * 10)

typedef struct sid_prefix_node {
	avl_node_t	avl_link;
	const char 	*sid_prefix;
} sid_prefix_node_t;


typedef struct sid2pid {
	avl_node_t	avl_link;
	const char 	*sid_prefix;
	uint32_t	rid;
	uid_t		uid;
	time_t		uid_ttl;
	gid_t		gid;
	time_t		gid_ttl;
	int		is_user;
} sid2pid_t;


typedef struct pid2sid {
	avl_node_t	avl_link;
	const char 	*sid_prefix;
	uint32_t	rid;
	uid_t		pid;
	time_t		ttl;
} pid2sid_t;




typedef int (*avl_comp_fn)(const void*, const void*);


struct sid_prefix_store {
	struct avl_tree	tree;
	krwlock_t	lock;
};

struct sid_prefix_store *kidmap_sid_prefix_store = NULL;



static void
kidmap_purge_sid2pid_avl(idmap_sid2pid_cache_t *cache, size_t limit);

static void
kidmap_purge_pid2sid_avl(idmap_pid2sid_cache_t *cache, size_t limit);


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
kidmap_compare_sid(const sid2pid_t *entry1, const sid2pid_t *entry2)
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
kidmap_compare_pid(const pid2sid_t *entry1, const pid2sid_t *entry2)
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
	avl_create(&cache->sid2pid.tree, (avl_comp_fn)kidmap_compare_sid,
	    sizeof (sid2pid_t), offsetof(sid2pid_t, avl_link));
	mutex_init(&cache->sid2pid.mutex, NULL, MUTEX_DEFAULT, NULL);
	cache->sid2pid.purge_time = 0;
	cache->sid2pid.prev = NULL;
	cache->sid2pid.uid_num = 0;
	cache->sid2pid.gid_num = 0;
	cache->sid2pid.pid_num = 0;

	avl_create(&cache->uid2sid.tree, (avl_comp_fn)kidmap_compare_pid,
	    sizeof (pid2sid_t), offsetof(pid2sid_t, avl_link));
	mutex_init(&cache->uid2sid.mutex, NULL, MUTEX_DEFAULT, NULL);
	cache->uid2sid.purge_time = 0;
	cache->uid2sid.prev = NULL;

	avl_create(&cache->gid2sid.tree, (avl_comp_fn)kidmap_compare_pid,
	    sizeof (pid2sid_t), offsetof(pid2sid_t, avl_link));
	mutex_init(&cache->gid2sid.mutex, NULL, MUTEX_DEFAULT, NULL);
	cache->gid2sid.purge_time = 0;
	cache->gid2sid.prev = NULL;
}


void
kidmap_cache_delete(idmap_cache_t *cache)
{
	sid2pid_t *sid2pid;
	pid2sid_t *pid2sid;
	void *cookie;

	cookie = NULL;
	while ((sid2pid = avl_destroy_nodes(&cache->sid2pid.tree, &cookie))
	    != NULL) {
		kmem_free(sid2pid, sizeof (sid2pid_t));
	}
	avl_destroy(&cache->sid2pid.tree);
	mutex_destroy(&cache->sid2pid.mutex);


	cookie = NULL;
	while ((pid2sid = avl_destroy_nodes(&cache->uid2sid.tree, &cookie))
	    != NULL) {
		kmem_free(pid2sid, sizeof (pid2sid_t));
	}
	avl_destroy(&cache->uid2sid.tree);
	mutex_destroy(&cache->uid2sid.mutex);


	cookie = NULL;
	while ((pid2sid = avl_destroy_nodes(&cache->gid2sid.tree, &cookie))
	    != NULL) {
		kmem_free(pid2sid, sizeof (pid2sid_t));
	}
	avl_destroy(&cache->gid2sid.tree);
	mutex_destroy(&cache->gid2sid.mutex);
}


void
kidmap_cache_get_data(idmap_cache_t *cache, size_t *uidbysid, size_t *gidbysid,
	size_t *pidbysid, size_t *sidbyuid, size_t *sidbygid)
{
	mutex_enter(&cache->sid2pid.mutex);
	*uidbysid = cache->sid2pid.uid_num;
	*gidbysid = cache->sid2pid.gid_num;
	*pidbysid = cache->sid2pid.pid_num;
	mutex_exit(&cache->sid2pid.mutex);

	mutex_enter(&cache->uid2sid.mutex);
	*sidbyuid = avl_numnodes(&cache->uid2sid.tree);
	mutex_exit(&cache->uid2sid.mutex);

	mutex_enter(&cache->gid2sid.mutex);
	*sidbygid = avl_numnodes(&cache->gid2sid.tree);
	mutex_exit(&cache->gid2sid.mutex);
}


void
kidmap_cache_purge(idmap_cache_t *cache)
{
	sid2pid_t *sid2pid;
	pid2sid_t *pid2sid;
	void *cookie;

	mutex_enter(&cache->sid2pid.mutex);
	cookie = NULL;
	while ((sid2pid = avl_destroy_nodes(&cache->sid2pid.tree, &cookie))
	    != NULL) {
		kmem_free(sid2pid, sizeof (sid2pid_t));
	}
	avl_destroy(&cache->sid2pid.tree);
	avl_create(&cache->sid2pid.tree, (avl_comp_fn)kidmap_compare_sid,
	    sizeof (sid2pid_t), offsetof(sid2pid_t, avl_link));
	cache->sid2pid.purge_time = 0;
	cache->sid2pid.prev = NULL;
	cache->sid2pid.uid_num = 0;
	cache->sid2pid.gid_num = 0;
	cache->sid2pid.pid_num = 0;
	mutex_exit(&cache->sid2pid.mutex);


	mutex_enter(&cache->uid2sid.mutex);
	cookie = NULL;
	while ((pid2sid = avl_destroy_nodes(&cache->uid2sid.tree, &cookie))
	    != NULL) {
		kmem_free(pid2sid, sizeof (pid2sid_t));
	}
	avl_destroy(&cache->uid2sid.tree);
	avl_create(&cache->uid2sid.tree, (avl_comp_fn)kidmap_compare_pid,
	    sizeof (pid2sid_t), offsetof(pid2sid_t, avl_link));
	cache->uid2sid.purge_time = 0;
	cache->uid2sid.prev = NULL;
	mutex_exit(&cache->uid2sid.mutex);


	mutex_enter(&cache->gid2sid.mutex);
	cookie = NULL;
	while ((pid2sid = avl_destroy_nodes(&cache->gid2sid.tree, &cookie))
	    != NULL) {
		kmem_free(pid2sid, sizeof (pid2sid_t));
	}
	avl_destroy(&cache->gid2sid.tree);
	avl_create(&cache->gid2sid.tree, (avl_comp_fn)kidmap_compare_pid,
	    sizeof (pid2sid_t), offsetof(pid2sid_t, avl_link));
	cache->gid2sid.purge_time = 0;
	cache->gid2sid.prev = NULL;
	mutex_exit(&cache->gid2sid.mutex);
}


int
kidmap_cache_lookup_uidbysid(idmap_cache_t *cache, const char *sid_prefix,
			uint32_t rid, uid_t *uid)
{
	sid2pid_t	entry;
	sid2pid_t	*result;
	avl_index_t	where;
	int		status;
	time_t		now = gethrestime_sec();

	entry.sid_prefix = sid_prefix;
	entry.rid = rid;

	mutex_enter(&cache->sid2pid.mutex);

	result = avl_find(&cache->sid2pid.tree, &entry, &where);

	if (result && result->uid != UNDEF_UID && result->uid_ttl > now) {
		*uid = result->uid;
		status = IDMAP_SUCCESS;
	} else
		status = IDMAP_ERR_NOMAPPING;

	mutex_exit(&cache->sid2pid.mutex);

	return (status);
}



int
kidmap_cache_lookup_gidbysid(idmap_cache_t *cache, const char *sid_prefix,
			uint32_t rid, gid_t *gid)
{
	sid2pid_t	entry;
	sid2pid_t	*result;
	avl_index_t	where;
	int		status;
	time_t		now = gethrestime_sec();

	entry.sid_prefix = sid_prefix;
	entry.rid = rid;

	mutex_enter(&cache->sid2pid.mutex);

	result = avl_find(&cache->sid2pid.tree, &entry, &where);

	if (result && result->gid != UNDEF_GID && result->gid_ttl > now) {
		*gid = result->gid;
		status = IDMAP_SUCCESS;
	} else
		status = IDMAP_ERR_NOMAPPING;

	mutex_exit(&cache->sid2pid.mutex);

	return (status);
}




int
kidmap_cache_lookup_pidbysid(idmap_cache_t *cache, const char *sid_prefix,
			uint32_t rid, uid_t *pid, int *is_user)
{
	sid2pid_t	entry;
	sid2pid_t	*result;
	avl_index_t	where;
	int		status;
	time_t		now = gethrestime_sec();

	entry.sid_prefix = sid_prefix;
	entry.rid = rid;

	mutex_enter(&cache->sid2pid.mutex);

	result = avl_find(&cache->sid2pid.tree, &entry, &where);

	if (result && result->is_user != UNDEF_ISUSER) {
		if (result->is_user && result->uid_ttl > now) {
			*pid = result->uid;
			*is_user = result->is_user;
			status = IDMAP_SUCCESS;
		} else if (!result->is_user && result->gid_ttl > now) {
			*pid = result->gid;
			*is_user = result->is_user;
			status = IDMAP_SUCCESS;
		} else
			status = IDMAP_ERR_NOMAPPING;
	} else
		status = IDMAP_ERR_NOMAPPING;

	mutex_exit(&cache->sid2pid.mutex);

	return (status);
}



int
kidmap_cache_lookup_sidbyuid(idmap_cache_t *cache, const char **sid_prefix,
			uint32_t *rid, uid_t uid)
{
	pid2sid_t	entry;
	pid2sid_t	*result;
	avl_index_t	where;
	int		status;
	time_t		now = gethrestime_sec();

	entry.pid = uid;

	mutex_enter(&cache->uid2sid.mutex);

	result = avl_find(&cache->uid2sid.tree, &entry, &where);

	if (result && result->ttl > now) {
		*sid_prefix = result->sid_prefix;
		*rid = result->rid;
		status = IDMAP_SUCCESS;
	} else
		status = IDMAP_ERR_NOMAPPING;

	mutex_exit(&cache->uid2sid.mutex);

	return (status);
}

int
kidmap_cache_lookup_sidbygid(idmap_cache_t *cache, const char **sid_prefix,
			uint32_t *rid, gid_t gid)
{
	pid2sid_t	entry;
	pid2sid_t	*result;
	avl_index_t	where;
	int		status;
	time_t		now = gethrestime_sec();

	entry.pid = gid;

	mutex_enter(&cache->gid2sid.mutex);

	result = avl_find(&cache->gid2sid.tree, &entry, &where);

	if (result && result->ttl > now) {
		*sid_prefix = result->sid_prefix;
		*rid = result->rid;
		status = IDMAP_SUCCESS;
	} else
		status = IDMAP_ERR_NOMAPPING;

	mutex_exit(&cache->gid2sid.mutex);

	return (status);
}





void
kidmap_cache_add_sid2uid(idmap_cache_t *cache, const char *sid_prefix,
			uint32_t rid, uid_t uid, int direction)

{
	avl_index_t	where;
	int		purge_required;
	time_t		ttl = CACHE_TTL + gethrestime_sec();


	if (direction == IDMAP_DIRECTION_BI ||
	    direction == IDMAP_DIRECTION_W2U) {
		sid2pid_t	find;
		sid2pid_t	*result;
		sid2pid_t	*new;

		purge_required = FALSE;
		find.sid_prefix = sid_prefix;
		find.rid = rid;

		mutex_enter(&cache->sid2pid.mutex);
		result = avl_find(&cache->sid2pid.tree, &find, &where);

		if (result) {
			if (result->uid == UNDEF_UID)
				cache->sid2pid.uid_num++;
			result->uid = uid;
			result->uid_ttl = ttl;
		} else {
			new = kmem_alloc(sizeof (sid2pid_t), KM_SLEEP);
			new->sid_prefix = sid_prefix;
			new->rid = rid;
			new->uid = uid;
			new->uid_ttl = ttl;
			new->gid = UNDEF_GID;
			new->gid_ttl = 0;
			new->is_user = UNDEF_ISUSER; /* Unknown */
			cache->sid2pid.uid_num++;

			avl_insert(&cache->sid2pid.tree, new, where);

			if ((avl_numnodes(&cache->sid2pid.tree) >
			    CACHE_PID_TRIGGER_SIZE) &&
			    (cache->sid2pid.purge_time + CACHE_PURGE_INTERVAL <
			    gethrestime_sec()))
				purge_required = TRUE;
		}

		mutex_exit(&cache->sid2pid.mutex);

		if (purge_required)
			kidmap_purge_sid2pid_avl(&cache->sid2pid,
			    CACHE_PID_TRIGGER_SIZE);
	}

	if (direction == IDMAP_DIRECTION_BI ||
	    direction == IDMAP_DIRECTION_U2W) {
		pid2sid_t	find;
		pid2sid_t	*result;
		pid2sid_t	*new;

		purge_required = FALSE;
		find.pid = uid;

		mutex_enter(&cache->uid2sid.mutex);
		result = avl_find(&cache->uid2sid.tree, &find, &where);

		if (result) {
			result->sid_prefix = sid_prefix;
			result->rid = rid;
			result->ttl = ttl;
		} else {
			new = kmem_alloc(sizeof (pid2sid_t), KM_SLEEP);
			new->sid_prefix = sid_prefix;
			new->rid = rid;
			new->pid = uid;
			new->ttl = ttl;

			avl_insert(&cache->uid2sid.tree, new, where);

			if ((avl_numnodes(&cache->uid2sid.tree) >
			    CACHE_UID_TRIGGER_SIZE) &&
			    (cache->uid2sid.purge_time + CACHE_PURGE_INTERVAL <
			    gethrestime_sec()))
				purge_required = TRUE;
		}
		mutex_exit(&cache->uid2sid.mutex);

		if (purge_required)
			kidmap_purge_pid2sid_avl(&cache->uid2sid,
			    CACHE_UID_TRIGGER_SIZE);
	}
}



void
kidmap_cache_add_sid2gid(idmap_cache_t *cache, const char *sid_prefix,
			uint32_t rid, gid_t gid, int direction)
{
	avl_index_t	where;
	int		purge_required;
	time_t		ttl = CACHE_TTL + gethrestime_sec();


	if (direction == IDMAP_DIRECTION_BI ||
	    direction == IDMAP_DIRECTION_W2U) {
		sid2pid_t	find;
		sid2pid_t	*result;
		sid2pid_t	*new;

		purge_required = FALSE;
		find.sid_prefix = sid_prefix;
		find.rid = rid;

		mutex_enter(&cache->sid2pid.mutex);
		result = avl_find(&cache->sid2pid.tree, &find, &where);

		if (result) {
			if (result->gid == UNDEF_GID)
				cache->sid2pid.gid_num++;
			result->gid = gid;
			result->gid_ttl = ttl;
		} else {
			new = kmem_alloc(sizeof (sid2pid_t), KM_SLEEP);
			new->sid_prefix = sid_prefix;
			new->rid = rid;
			new->uid = UNDEF_UID;
			new->uid_ttl = 0;
			new->gid = gid;
			new->gid_ttl = ttl;
			new->is_user = UNDEF_ISUSER; /* Unknown */
			cache->sid2pid.gid_num++;

			avl_insert(&cache->sid2pid.tree, new, where);

			if ((avl_numnodes(&cache->sid2pid.tree) >
			    CACHE_PID_TRIGGER_SIZE) &&
			    (cache->sid2pid.purge_time + CACHE_PURGE_INTERVAL <
			    gethrestime_sec()))
				purge_required = TRUE;
		}
		mutex_exit(&cache->sid2pid.mutex);

		if (purge_required)
			kidmap_purge_sid2pid_avl(&cache->sid2pid,
			    CACHE_PID_TRIGGER_SIZE);
	}

	if (direction == IDMAP_DIRECTION_BI ||
	    direction == IDMAP_DIRECTION_U2W) {
		pid2sid_t	find;
		pid2sid_t	*result;
		pid2sid_t	*new;

		purge_required = FALSE;
		find.pid = gid;

		mutex_enter(&cache->gid2sid.mutex);
		result = avl_find(&cache->gid2sid.tree, &find, &where);

		if (result) {
			result->sid_prefix = sid_prefix;
			result->rid = rid;
			result->ttl = ttl;
		} else {
			new = kmem_alloc(sizeof (pid2sid_t), KM_SLEEP);
			new->sid_prefix = sid_prefix;
			new->rid = rid;
			new->pid = gid;
			new->ttl = ttl;

			avl_insert(&cache->gid2sid.tree, new, where);

			if ((avl_numnodes(&cache->gid2sid.tree) >
			    CACHE_GID_TRIGGER_SIZE) &&
			    (cache->gid2sid.purge_time + CACHE_PURGE_INTERVAL <
			    gethrestime_sec()))
				purge_required = TRUE;
		}
		mutex_exit(&cache->gid2sid.mutex);

		if (purge_required)
			kidmap_purge_pid2sid_avl(&cache->gid2sid,
			    CACHE_GID_TRIGGER_SIZE);
	}
}


void
kidmap_cache_add_sid2pid(idmap_cache_t *cache, const char *sid_prefix,
			uint32_t rid, uid_t pid, int is_user, int direction)
{
	avl_index_t	where;
	int		purge_required;
	time_t		ttl = CACHE_TTL + gethrestime_sec();


	if (direction == IDMAP_DIRECTION_BI ||
	    direction == IDMAP_DIRECTION_W2U) {
		sid2pid_t	find;
		sid2pid_t	*result;
		sid2pid_t	*new;

		purge_required = FALSE;
		find.sid_prefix = sid_prefix;
		find.rid = rid;

		mutex_enter(&cache->sid2pid.mutex);
		result = avl_find(&cache->sid2pid.tree, &find, &where);

		if (result) {
			if (result->is_user == UNDEF_ISUSER)
				cache->sid2pid.pid_num++;
			result->is_user = is_user;
			if (is_user) {
				if (result->uid == UNDEF_UID)
					cache->sid2pid.uid_num++;
				result->uid = pid;
				result->uid_ttl = ttl;
			} else {
				if (result->gid == UNDEF_GID)
					cache->sid2pid.gid_num++;
				result->gid = pid;
				result->gid_ttl = ttl;
			}
		} else {
			new = kmem_alloc(sizeof (sid2pid_t), KM_SLEEP);
			new->sid_prefix = sid_prefix;
			new->rid = rid;
			new->is_user = is_user;
			if (is_user) {
				new->uid = pid;
				new->uid_ttl = ttl;
				new->gid = UNDEF_GID;
				new->gid_ttl = 0;
				cache->sid2pid.uid_num++;
			} else {
				new->uid = UNDEF_UID;
				new->uid_ttl = 0;
				new->gid = pid;
				new->gid_ttl = ttl;
				cache->sid2pid.gid_num++;
			}
			cache->sid2pid.pid_num++;

			avl_insert(&cache->sid2pid.tree, new, where);

			if ((avl_numnodes(&cache->sid2pid.tree) >
			    CACHE_PID_TRIGGER_SIZE) &&
			    (cache->sid2pid.purge_time + CACHE_PURGE_INTERVAL <
			    gethrestime_sec()))
				purge_required = TRUE;
		}
		mutex_exit(&cache->sid2pid.mutex);

		if (purge_required)
			kidmap_purge_sid2pid_avl(&cache->sid2pid,
			    CACHE_PID_TRIGGER_SIZE);
	}

	if (direction == IDMAP_DIRECTION_BI ||
	    direction == IDMAP_DIRECTION_U2W) {
		pid2sid_t	find;
		pid2sid_t	*result;
		pid2sid_t	*new;

		purge_required = FALSE;
		find.pid = pid;
		if (is_user) {
			mutex_enter(&cache->uid2sid.mutex);
			result = avl_find(&cache->uid2sid.tree, &find, &where);

			if (result) {
				result->sid_prefix = sid_prefix;
				result->rid = rid;
				result->ttl = ttl;
			} else {
				new = kmem_alloc(sizeof (pid2sid_t), KM_SLEEP);
				new->sid_prefix = sid_prefix;
				new->rid = rid;
				new->pid = pid;
				new->ttl = ttl;

				avl_insert(&cache->uid2sid.tree, new, where);

				if ((avl_numnodes(&cache->uid2sid.tree) >
				    CACHE_UID_TRIGGER_SIZE) &&
				    (cache->uid2sid.purge_time +
				    CACHE_PURGE_INTERVAL <
				    gethrestime_sec()))
					purge_required = TRUE;
			}
			mutex_exit(&cache->uid2sid.mutex);

			if (purge_required)
				kidmap_purge_pid2sid_avl(&cache->uid2sid,
				    CACHE_UID_TRIGGER_SIZE);
		} else {
			mutex_enter(&cache->gid2sid.mutex);
			result = avl_find(&cache->gid2sid.tree, &find, &where);

			if (result) {
				result->sid_prefix = sid_prefix;
				result->rid = rid;
				result->ttl = ttl;
			} else {
				new = kmem_alloc(sizeof (pid2sid_t), KM_SLEEP);
				new->sid_prefix = sid_prefix;
				new->rid = rid;
				new->pid = pid;
				new->ttl = ttl;

				avl_insert(&cache->gid2sid.tree, new, where);

				if ((avl_numnodes(&cache->gid2sid.tree) >
				    CACHE_GID_TRIGGER_SIZE) &&
				    (cache->gid2sid.purge_time +
				    CACHE_PURGE_INTERVAL <
				    gethrestime_sec()))
					purge_required = TRUE;

			}
			mutex_exit(&cache->gid2sid.mutex);

			if (purge_required)
				kidmap_purge_pid2sid_avl(&cache->gid2sid,
				    CACHE_GID_TRIGGER_SIZE);
		}
	}
}





static void
kidmap_purge_sid2pid_avl(idmap_sid2pid_cache_t *avl, size_t limit)
{
	time_t		now = gethrestime_sec();
	sid2pid_t	*curr;
	sid2pid_t	*prev;
	sid2pid_t	*start;
	int		last = FALSE;

	mutex_enter(&avl->mutex);
	if (avl_numnodes(&avl->tree) <= limit) {
		mutex_exit(&avl->mutex);
		return;
	}

	if (avl->prev == NULL)
		start = avl_first(&avl->tree);
	else
		start = avl->prev;

	prev = start;
	curr = AVL_NEXT(&avl->tree, prev);
	if (curr == NULL)
		curr = avl_first(&avl->tree);

	while (!last && avl_numnodes(&avl->tree) > limit) {
		if (curr == start)
			last = TRUE;
		if (curr->uid_ttl < now && curr->gid_ttl < now) {
			/* Old entry to remove */
			avl_remove(&avl->tree, curr);
			if (curr->uid != UNDEF_UID)
				avl->uid_num--;
			if (curr->gid != UNDEF_GID)
				avl->gid_num--;
			if (curr->is_user != UNDEF_ISUSER)
				avl->pid_num--;
			kmem_free(curr, sizeof (sid2pid_t));
			curr = AVL_NEXT(&avl->tree, prev);
			if (curr == NULL)
				curr = avl_first(&avl->tree);
			continue;
		}
		prev = curr;
		curr = AVL_NEXT(&avl->tree, curr);
		if (curr == NULL)
			curr = avl_first(&avl->tree);
	}
	avl->purge_time = now;
	avl->prev = prev;

	mutex_exit(&avl->mutex);
}


static void
kidmap_purge_pid2sid_avl(idmap_pid2sid_cache_t *avl, size_t limit)
{
	time_t		now = gethrestime_sec();
	pid2sid_t	*curr;
	pid2sid_t	*prev = NULL;
	pid2sid_t	*start;
	int		last = FALSE;

	mutex_enter(&avl->mutex);
	if (avl_numnodes(&avl->tree) <= limit) {
		mutex_exit(&avl->mutex);
		return;
	}

	if (avl->prev == NULL)
		start = avl_first(&avl->tree);
	else
		start = avl->prev;

	prev = start;
	curr = AVL_NEXT(&avl->tree, prev);
	if (curr == NULL)
		curr = avl_first(&avl->tree);

	while (!last && avl_numnodes(&avl->tree) > limit) {
		if (curr == start)
			last = TRUE;
		if (curr->ttl < now) {
			/* Old entry to remove */
			avl_remove(&avl->tree, curr);
			kmem_free(curr, sizeof (pid2sid_t));
			curr = AVL_NEXT(&avl->tree, prev);
			if (curr == NULL)
				curr = avl_first(&avl->tree);
			continue;
		}
		prev = curr;
		curr = AVL_NEXT(&avl->tree, curr);
		if (curr == NULL)
			curr = avl_first(&avl->tree);
	}
	avl->purge_time = now;
	avl->prev = prev;

	mutex_exit(&avl->mutex);
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
