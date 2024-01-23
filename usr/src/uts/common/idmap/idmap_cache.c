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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright 2023 RackTop Systems, Inc.
 */

/*
 * Windows to Solaris Identity Mapping kernel API
 * This module provides the kernel cache.
 */


#include <sys/types.h>
#include <sys/avl.h>
#include <sys/systm.h>
#include <sys/sysmacros.h>
#include <sys/ksynch.h>
#include <sys/kidmap.h>
#include <rpcsvc/idmap_prot.h>
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



#define	list_insert(head, ele)\
	do {\
		(ele)->flink = (head)->flink;\
		(head)->flink = (ele);\
		(ele)->blink = (ele)->flink->blink;\
		(ele)->flink->blink = (ele);\
	} while (0)



#define	list_remove(ele)\
	do {\
		(ele)->flink->blink = (ele)->blink;\
		(ele)->blink->flink = (ele)->flink;\
	} while (0)


#define	list_move(head, ele) \
	do {\
		if ((head)->flink != (ele)) {\
			list_remove(ele);\
			list_insert(head, ele);\
		}\
	} while (0)


typedef struct sid_prefix_node {
	avl_node_t	avl_link;
	const char 	*sid_prefix;
} sid_prefix_node_t;


struct sid_prefix_store {
	struct avl_tree	tree;
	krwlock_t	lock;
};

struct sid_prefix_store *kidmap_sid_prefix_store = NULL;



static void
kidmap_purge_sid2pid_cache(idmap_sid2pid_cache_t *cache, size_t limit);

static void
kidmap_purge_pid2sid_cache(idmap_pid2sid_cache_t *cache, size_t limit);


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
kidmap_compare_sid(const void *p1, const void *p2)
{
	const sid2pid_t *entry1 = p1;
	const sid2pid_t *entry2 = p2;
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
kidmap_compare_pid(const void *p1, const void *p2)
{
	const pid2sid_t *entry1 = p1;
	const pid2sid_t *entry2 = p2;

	if (entry2->pid > entry1->pid)
		return (1);
	if (entry2->pid < entry1->pid)
		return (-1);
	return (0);
}


static int
kidmap_compare_sid_prefix(const void *p1, const void *p2)
{
	const sid_prefix_node_t *entry1 = p1;
	const sid_prefix_node_t *entry2 = p2;
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
	int i;

	/*
	 * Create SID-2-PID hash table
	 */
	for (i = 0; i < KIDMAP_HASH_SIZE; i++) {
		idmap_sid2pid_cache_t *sid2pid_hb = &cache->sid2pid_hash[i];

		avl_create(&sid2pid_hb->tree, kidmap_compare_sid,
		    sizeof (sid2pid_t), offsetof(sid2pid_t, avl_link));
		mutex_init(&sid2pid_hb->mutex, NULL, MUTEX_DEFAULT, NULL);
		sid2pid_hb->purge_time = 0;
		sid2pid_hb->head.flink = &sid2pid_hb->head;
		sid2pid_hb->head.blink = &sid2pid_hb->head;
		sid2pid_hb->uid_num = 0;
		sid2pid_hb->gid_num = 0;
		sid2pid_hb->pid_num = 0;
	}

	/*
	 * Create UID-2-SID hash table
	 */
	for (i = 0; i < KIDMAP_HASH_SIZE; i++) {
		idmap_pid2sid_cache_t *uid2sid_hb = &cache->uid2sid_hash[i];

		avl_create(&uid2sid_hb->tree, kidmap_compare_pid,
		    sizeof (pid2sid_t), offsetof(pid2sid_t, avl_link));
		mutex_init(&uid2sid_hb->mutex, NULL, MUTEX_DEFAULT, NULL);
		uid2sid_hb->purge_time = 0;
		uid2sid_hb->head.flink = &uid2sid_hb->head;
		uid2sid_hb->head.blink = &uid2sid_hb->head;
	}

	/*
	 * Create GID-2-SID hash table
	 */
	for (i = 0; i < KIDMAP_HASH_SIZE; i++) {
		idmap_pid2sid_cache_t *gid2sid_hb  = &cache->gid2sid_hash[i];

		avl_create(&gid2sid_hb->tree, kidmap_compare_pid,
		    sizeof (pid2sid_t), offsetof(pid2sid_t, avl_link));
		mutex_init(&gid2sid_hb->mutex, NULL, MUTEX_DEFAULT, NULL);
		gid2sid_hb->purge_time = 0;
		gid2sid_hb->head.flink = &gid2sid_hb->head;
		gid2sid_hb->head.blink = &gid2sid_hb->head;
	}
}


void
kidmap_cache_delete(idmap_cache_t *cache)
{
	void *cookie;
	int i;

	for (i = 0; i < KIDMAP_HASH_SIZE; i++) {
		idmap_sid2pid_cache_t *sid2pid_hb = &cache->sid2pid_hash[i];
		sid2pid_t *sid2pid;

		cookie = NULL;
		while ((sid2pid = avl_destroy_nodes(&sid2pid_hb->tree,
		    &cookie)) != NULL) {
			kmem_free(sid2pid, sizeof (sid2pid_t));
		}
		avl_destroy(&sid2pid_hb->tree);
		mutex_destroy(&sid2pid_hb->mutex);
	}

	for (i = 0; i < KIDMAP_HASH_SIZE; i++) {
		idmap_pid2sid_cache_t *uid2sid_hb = &cache->uid2sid_hash[i];
		pid2sid_t *uid2sid;

		cookie = NULL;
		while ((uid2sid = avl_destroy_nodes(&uid2sid_hb->tree,
		    &cookie)) != NULL) {
			kmem_free(uid2sid, sizeof (pid2sid_t));
		}
		avl_destroy(&uid2sid_hb->tree);
		mutex_destroy(&uid2sid_hb->mutex);
	}

	for (i = 0; i < KIDMAP_HASH_SIZE; i++) {
		idmap_pid2sid_cache_t *gid2sid_hb = &cache->gid2sid_hash[i];
		pid2sid_t *gid2sid;

		cookie = NULL;
		while ((gid2sid = avl_destroy_nodes(&gid2sid_hb->tree,
		    &cookie)) != NULL) {
			kmem_free(gid2sid, sizeof (pid2sid_t));
		}
		avl_destroy(&gid2sid_hb->tree);
		mutex_destroy(&gid2sid_hb->mutex);
	}
}


/*
 * Get counts of cache entries
 */
void
kidmap_cache_get_data(idmap_cache_t *cache, size_t *uidbysid, size_t *gidbysid,
	size_t *pidbysid, size_t *sidbyuid, size_t *sidbygid)
{
	int i;

	*uidbysid = 0;
	*gidbysid = 0;
	*pidbysid = 0;
	*sidbyuid = 0;
	*sidbygid = 0;


	for (i = 0; i < KIDMAP_HASH_SIZE; i++) {
		idmap_sid2pid_cache_t *sid2pid_hb = &cache->sid2pid_hash[i];

		mutex_enter(&sid2pid_hb->mutex);
		*uidbysid += sid2pid_hb->uid_num;
		*gidbysid += sid2pid_hb->gid_num;
		*pidbysid += sid2pid_hb->pid_num;
		mutex_exit(&sid2pid_hb->mutex);
	}

	for (i = 0; i < KIDMAP_HASH_SIZE; i++) {
		idmap_pid2sid_cache_t *uid2sid_hb = &cache->uid2sid_hash[i];

		mutex_enter(&uid2sid_hb->mutex);
		*sidbyuid += avl_numnodes(&uid2sid_hb->tree);
		mutex_exit(&uid2sid_hb->mutex);
	}

	for (i = 0; i < KIDMAP_HASH_SIZE; i++) {
		idmap_pid2sid_cache_t *gid2sid_hb = &cache->gid2sid_hash[i];

		mutex_enter(&gid2sid_hb->mutex);
		*sidbygid += avl_numnodes(&gid2sid_hb->tree);
		mutex_exit(&gid2sid_hb->mutex);
	}
}


void
kidmap_cache_purge(idmap_cache_t *cache)
{
	void *cookie;
	int i;

	for (i = 0; i < KIDMAP_HASH_SIZE; i++) {
		idmap_sid2pid_cache_t *sid2pid_hb = &cache->sid2pid_hash[i];
		sid2pid_t *sid2pid;

		mutex_enter(&sid2pid_hb->mutex);
		cookie = NULL;
		while ((sid2pid = avl_destroy_nodes(&sid2pid_hb->tree,
		    &cookie)) != NULL) {
			kmem_free(sid2pid, sizeof (sid2pid_t));
		}
		avl_destroy(&sid2pid_hb->tree);
		avl_create(&sid2pid_hb->tree, kidmap_compare_sid,
		    sizeof (sid2pid_t), offsetof(sid2pid_t, avl_link));
		sid2pid_hb->purge_time = 0;
		sid2pid_hb->head.flink = &sid2pid_hb->head;
		sid2pid_hb->head.blink = &sid2pid_hb->head;
		sid2pid_hb->uid_num = 0;
		sid2pid_hb->gid_num = 0;
		sid2pid_hb->pid_num = 0;
		mutex_exit(&sid2pid_hb->mutex);
	}

	for (i = 0; i < KIDMAP_HASH_SIZE; i++) {
		idmap_pid2sid_cache_t *uid2sid_hb = &cache->uid2sid_hash[i];
		pid2sid_t *uid2sid;

		mutex_enter(&uid2sid_hb->mutex);
		cookie = NULL;
		while ((uid2sid = avl_destroy_nodes(&uid2sid_hb->tree,
		    &cookie)) != NULL) {
			kmem_free(uid2sid, sizeof (pid2sid_t));
		}
		avl_destroy(&uid2sid_hb->tree);
		avl_create(&uid2sid_hb->tree, kidmap_compare_pid,
		    sizeof (pid2sid_t), offsetof(pid2sid_t, avl_link));
		uid2sid_hb->purge_time = 0;
		uid2sid_hb->head.flink = &uid2sid_hb->head;
		uid2sid_hb->head.blink = &uid2sid_hb->head;
		mutex_exit(&uid2sid_hb->mutex);
	}

	for (i = 0; i < KIDMAP_HASH_SIZE; i++) {
		idmap_pid2sid_cache_t *gid2sid_hb = &cache->gid2sid_hash[i];
		pid2sid_t *gid2sid;

		mutex_enter(&gid2sid_hb->mutex);
		cookie = NULL;
		while ((gid2sid = avl_destroy_nodes(&gid2sid_hb->tree,
		    &cookie)) != NULL) {
			kmem_free(gid2sid, sizeof (pid2sid_t));
		}
		avl_destroy(&gid2sid_hb->tree);
		avl_create(&gid2sid_hb->tree, kidmap_compare_pid,
		    sizeof (pid2sid_t), offsetof(pid2sid_t, avl_link));
		gid2sid_hb->purge_time = 0;
		gid2sid_hb->head.flink = &gid2sid_hb->head;
		gid2sid_hb->head.blink = &gid2sid_hb->head;
		mutex_exit(&gid2sid_hb->mutex);
	}
}


int
kidmap_cache_lookup_uidbysid(idmap_cache_t *cache, const char *sid_prefix,
			uint32_t rid, uid_t *uid)
{
	sid2pid_t	entry;
	sid2pid_t	*result;
	avl_index_t	where;
	int		status = IDMAP_ERR_NOMAPPING;
	int		idx = (rid & KIDMAP_HASH_MASK);
	idmap_sid2pid_cache_t *sid2pid_hb = &cache->sid2pid_hash[idx];
	time_t		now = gethrestime_sec();

	entry.sid_prefix = sid_prefix;
	entry.rid = rid;

	mutex_enter(&sid2pid_hb->mutex);

	result = avl_find(&sid2pid_hb->tree, &entry, &where);
	if (result != NULL) {
		list_move(&sid2pid_hb->head, result);
		if (result->uid != UNDEF_UID && result->uid_ttl > now) {
			*uid = result->uid;
			status = IDMAP_SUCCESS;
		}
	}

	mutex_exit(&sid2pid_hb->mutex);

	return (status);
}


int
kidmap_cache_lookup_gidbysid(idmap_cache_t *cache, const char *sid_prefix,
			uint32_t rid, gid_t *gid)
{
	sid2pid_t	entry;
	sid2pid_t	*result;
	avl_index_t	where;
	int		status = IDMAP_ERR_NOMAPPING;
	int		idx = (rid & KIDMAP_HASH_MASK);
	idmap_sid2pid_cache_t *sid2pid_hb = &cache->sid2pid_hash[idx];
	time_t		now = gethrestime_sec();

	entry.sid_prefix = sid_prefix;
	entry.rid = rid;

	mutex_enter(&sid2pid_hb->mutex);

	result = avl_find(&sid2pid_hb->tree, &entry, &where);
	if (result != NULL) {
		list_move(&sid2pid_hb->head, result);
		if (result->gid != UNDEF_GID && result->gid_ttl > now) {
			*gid = result->gid;
			status = IDMAP_SUCCESS;
		}
	}

	mutex_exit(&sid2pid_hb->mutex);

	return (status);
}


int
kidmap_cache_lookup_pidbysid(idmap_cache_t *cache, const char *sid_prefix,
			uint32_t rid, uid_t *pid, int *is_user)
{
	sid2pid_t	entry;
	sid2pid_t	*result;
	avl_index_t	where;
	int		status = IDMAP_ERR_NOMAPPING;
	int		idx = (rid & KIDMAP_HASH_MASK);
	idmap_sid2pid_cache_t *sid2pid_hb = &cache->sid2pid_hash[idx];
	time_t		now = gethrestime_sec();

	entry.sid_prefix = sid_prefix;
	entry.rid = rid;

	mutex_enter(&sid2pid_hb->mutex);

	result = avl_find(&sid2pid_hb->tree, &entry, &where);
	if (result != NULL) {
		list_move(&sid2pid_hb->head, result);
		if (result->is_user != UNDEF_ISUSER) {
			if (result->is_user && result->uid_ttl > now) {
				*pid = result->uid;
				*is_user = result->is_user;
				status = IDMAP_SUCCESS;
			} else if (!result->is_user && result->gid_ttl > now) {
				*pid = result->gid;
				*is_user = result->is_user;
				status = IDMAP_SUCCESS;
			}
		}
	}

	mutex_exit(&sid2pid_hb->mutex);

	return (status);
}



int
kidmap_cache_lookup_sidbyuid(idmap_cache_t *cache, const char **sid_prefix,
			uint32_t *rid, uid_t uid)
{
	pid2sid_t	entry;
	pid2sid_t	*result;
	avl_index_t	where;
	int		status = IDMAP_ERR_NOMAPPING;
	int		idx = (uid & KIDMAP_HASH_MASK);
	idmap_pid2sid_cache_t *uid2sid_hb = &cache->uid2sid_hash[idx];
	time_t		now = gethrestime_sec();

	entry.pid = uid;

	mutex_enter(&uid2sid_hb->mutex);

	result = avl_find(&uid2sid_hb->tree, &entry, &where);
	if (result != NULL) {
		list_move(&uid2sid_hb->head, result);
		if (result->ttl > now) {
			*sid_prefix = result->sid_prefix;
			*rid = result->rid;
			status = IDMAP_SUCCESS;
		}
	}

	mutex_exit(&uid2sid_hb->mutex);

	return (status);
}


int
kidmap_cache_lookup_sidbygid(idmap_cache_t *cache, const char **sid_prefix,
			uint32_t *rid, gid_t gid)
{
	pid2sid_t	entry;
	pid2sid_t	*result;
	avl_index_t	where;
	int		status = IDMAP_ERR_NOMAPPING;
	int		idx = (gid & KIDMAP_HASH_MASK);
	idmap_pid2sid_cache_t *gid2sid_hb = &cache->gid2sid_hash[idx];
	time_t		now = gethrestime_sec();

	entry.pid = gid;

	mutex_enter(&gid2sid_hb->mutex);

	result = avl_find(&gid2sid_hb->tree, &entry, &where);
	if (result != NULL) {
		list_move(&gid2sid_hb->head, result);
		if (result->ttl > now) {
			*sid_prefix = result->sid_prefix;
			*rid = result->rid;
			status = IDMAP_SUCCESS;
		}
	}

	mutex_exit(&gid2sid_hb->mutex);

	return (status);
}


void
kidmap_cache_add_sid2uid(idmap_cache_t *cache, const char *sid_prefix,
			uint32_t rid, uid_t uid, int direction)

{
	avl_index_t	where;
	time_t		ttl = CACHE_TTL + gethrestime_sec();


	if (direction == IDMAP_DIRECTION_BI ||
	    direction == IDMAP_DIRECTION_W2U) {
		sid2pid_t	find;
		sid2pid_t	*result;
		sid2pid_t	*new;
		idmap_sid2pid_cache_t *sid2pid_hb =
		    &cache->sid2pid_hash[rid & KIDMAP_HASH_MASK];

		find.sid_prefix = sid_prefix;
		find.rid = rid;

		mutex_enter(&sid2pid_hb->mutex);

		result = avl_find(&sid2pid_hb->tree, &find, &where);
		if (result) {
			if (result->uid == UNDEF_UID)
				sid2pid_hb->uid_num++;
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
			sid2pid_hb->uid_num++;

			list_insert(&sid2pid_hb->head, new);
			avl_insert(&sid2pid_hb->tree, new, where);
		}

		if ((avl_numnodes(&sid2pid_hb->tree) >
		    CACHE_PID_TRIGGER_SIZE) &&
		    (sid2pid_hb->purge_time + CACHE_PURGE_INTERVAL <
		    gethrestime_sec()))
			kidmap_purge_sid2pid_cache(sid2pid_hb,
			    CACHE_PID_TRIGGER_SIZE);

		mutex_exit(&sid2pid_hb->mutex);
	}

	if (direction == IDMAP_DIRECTION_BI ||
	    direction == IDMAP_DIRECTION_U2W) {
		pid2sid_t	find;
		pid2sid_t	*result;
		pid2sid_t	*new;
		idmap_pid2sid_cache_t *uid2sid_hb =
		    &cache->uid2sid_hash[uid & KIDMAP_HASH_MASK];

		find.pid = uid;

		mutex_enter(&uid2sid_hb->mutex);

		result = avl_find(&uid2sid_hb->tree, &find, &where);
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

			list_insert(&uid2sid_hb->head, new);
			avl_insert(&uid2sid_hb->tree, new, where);
		}

		if ((avl_numnodes(&uid2sid_hb->tree) >
		    CACHE_UID_TRIGGER_SIZE) &&
		    (uid2sid_hb->purge_time + CACHE_PURGE_INTERVAL <
		    gethrestime_sec()))
			kidmap_purge_pid2sid_cache(uid2sid_hb,
			    CACHE_UID_TRIGGER_SIZE);

		mutex_exit(&uid2sid_hb->mutex);
	}
}



void
kidmap_cache_add_sid2gid(idmap_cache_t *cache, const char *sid_prefix,
			uint32_t rid, gid_t gid, int direction)
{
	avl_index_t	where;
	time_t		ttl = CACHE_TTL + gethrestime_sec();


	if (direction == IDMAP_DIRECTION_BI ||
	    direction == IDMAP_DIRECTION_W2U) {
		sid2pid_t	find;
		sid2pid_t	*result;
		sid2pid_t	*new;
		idmap_sid2pid_cache_t *sid2pid_hb =
		    &cache->sid2pid_hash[rid & KIDMAP_HASH_MASK];

		find.sid_prefix = sid_prefix;
		find.rid = rid;

		mutex_enter(&sid2pid_hb->mutex);

		result = avl_find(&sid2pid_hb->tree, &find, &where);
		if (result) {
			if (result->gid == UNDEF_GID)
				sid2pid_hb->gid_num++;
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
			sid2pid_hb->gid_num++;

			list_insert(&sid2pid_hb->head, new);
			avl_insert(&sid2pid_hb->tree, new, where);
		}

		if ((avl_numnodes(&sid2pid_hb->tree) >
		    CACHE_PID_TRIGGER_SIZE) &&
		    (sid2pid_hb->purge_time + CACHE_PURGE_INTERVAL <
		    gethrestime_sec()))
			kidmap_purge_sid2pid_cache(sid2pid_hb,
			    CACHE_PID_TRIGGER_SIZE);

		mutex_exit(&sid2pid_hb->mutex);
	}

	if (direction == IDMAP_DIRECTION_BI ||
	    direction == IDMAP_DIRECTION_U2W) {
		pid2sid_t	find;
		pid2sid_t	*result;
		pid2sid_t	*new;
		idmap_pid2sid_cache_t *gid2sid_hb =
		    &cache->gid2sid_hash[gid & KIDMAP_HASH_MASK];

		find.pid = gid;

		mutex_enter(&gid2sid_hb->mutex);

		result = avl_find(&gid2sid_hb->tree, &find, &where);
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

			list_insert(&gid2sid_hb->head, new);
			avl_insert(&gid2sid_hb->tree, new, where);
		}

		if ((avl_numnodes(&gid2sid_hb->tree) >
		    CACHE_GID_TRIGGER_SIZE) &&
		    (gid2sid_hb->purge_time + CACHE_PURGE_INTERVAL <
		    gethrestime_sec()))
			kidmap_purge_pid2sid_cache(gid2sid_hb,
			    CACHE_GID_TRIGGER_SIZE);

		mutex_exit(&gid2sid_hb->mutex);
	}
}


void
kidmap_cache_add_sid2pid(idmap_cache_t *cache, const char *sid_prefix,
			uint32_t rid, uid_t pid, int is_user, int direction)
{
	avl_index_t	where;
	time_t		ttl = CACHE_TTL + gethrestime_sec();


	if (direction == IDMAP_DIRECTION_BI ||
	    direction == IDMAP_DIRECTION_W2U) {
		sid2pid_t	find;
		sid2pid_t	*result;
		sid2pid_t	*new;
		idmap_sid2pid_cache_t *sid2pid_hb =
		    &cache->sid2pid_hash[rid & KIDMAP_HASH_MASK];

		find.sid_prefix = sid_prefix;
		find.rid = rid;

		mutex_enter(&sid2pid_hb->mutex);

		result = avl_find(&sid2pid_hb->tree, &find, &where);
		if (result) {
			if (result->is_user == UNDEF_ISUSER)
				sid2pid_hb->pid_num++;
			result->is_user = is_user;
			if (is_user) {
				if (result->uid == UNDEF_UID)
					sid2pid_hb->uid_num++;
				result->uid = pid;
				result->uid_ttl = ttl;
			} else {
				if (result->gid == UNDEF_GID)
					sid2pid_hb->gid_num++;
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
				sid2pid_hb->uid_num++;
			} else {
				new->uid = UNDEF_UID;
				new->uid_ttl = 0;
				new->gid = pid;
				new->gid_ttl = ttl;
				sid2pid_hb->gid_num++;
			}
			sid2pid_hb->pid_num++;

			list_insert(&sid2pid_hb->head, new);
			avl_insert(&sid2pid_hb->tree, new, where);
		}

		if ((avl_numnodes(&sid2pid_hb->tree) >
		    CACHE_PID_TRIGGER_SIZE) &&
		    (sid2pid_hb->purge_time + CACHE_PURGE_INTERVAL <
		    gethrestime_sec()))
			kidmap_purge_sid2pid_cache(sid2pid_hb,
			    CACHE_PID_TRIGGER_SIZE);

		mutex_exit(&sid2pid_hb->mutex);
	}

	if (direction == IDMAP_DIRECTION_BI ||
	    direction == IDMAP_DIRECTION_U2W) {
		pid2sid_t	find;
		pid2sid_t	*result;
		pid2sid_t	*new;
		int		idx = pid & KIDMAP_HASH_MASK;

		find.pid = pid;
		if (is_user) {
			idmap_pid2sid_cache_t *uid2sid_hb =
				&cache->uid2sid_hash[idx];

			mutex_enter(&uid2sid_hb->mutex);

			result = avl_find(&uid2sid_hb->tree, &find, &where);
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

				list_insert(&uid2sid_hb->head, new);
				avl_insert(&uid2sid_hb->tree, new, where);
			}

			if ((avl_numnodes(&uid2sid_hb->tree) >
			    CACHE_UID_TRIGGER_SIZE) &&
			    (uid2sid_hb->purge_time +
			    CACHE_PURGE_INTERVAL <
			    gethrestime_sec()))
				kidmap_purge_pid2sid_cache(uid2sid_hb,
				    CACHE_UID_TRIGGER_SIZE);

			mutex_exit(&uid2sid_hb->mutex);
		} else {
			idmap_pid2sid_cache_t *gid2sid_hb =
			    &cache->gid2sid_hash[idx];

			mutex_enter(&gid2sid_hb->mutex);

			result = avl_find(&gid2sid_hb->tree, &find, &where);
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

				list_insert(&gid2sid_hb->head, new);
				avl_insert(&gid2sid_hb->tree, new, where);
			}

			if ((avl_numnodes(&gid2sid_hb->tree) >
			    CACHE_GID_TRIGGER_SIZE) &&
			    (gid2sid_hb->purge_time +
			    CACHE_PURGE_INTERVAL < gethrestime_sec()))
				kidmap_purge_pid2sid_cache(gid2sid_hb,
				    CACHE_GID_TRIGGER_SIZE);

			mutex_exit(&gid2sid_hb->mutex);
		}
	}
}





static void
kidmap_purge_sid2pid_cache(idmap_sid2pid_cache_t *cache, size_t limit)
{
	time_t		now = gethrestime_sec();
	sid2pid_t	*item;

	while (avl_numnodes(&cache->tree) > limit) {
		/* Remove least recently used */
		item = cache->head.blink;
		list_remove(item);
		avl_remove(&cache->tree, item);
		if (item->uid != UNDEF_UID)
			cache->uid_num--;
		if (item->gid != UNDEF_GID)
			cache->gid_num--;
		if (item->is_user != UNDEF_ISUSER)
			cache->pid_num--;
		kmem_free(item, sizeof (sid2pid_t));
	}
	cache->purge_time = now;
}


static void
kidmap_purge_pid2sid_cache(idmap_pid2sid_cache_t *cache, size_t limit)
{
	time_t		now = gethrestime_sec();
	pid2sid_t	*item;

	while (avl_numnodes(&cache->tree) > limit) {
		/* Remove least recently used */
		item = cache->head.blink;
		list_remove(item);
		avl_remove(&cache->tree, item);
		kmem_free(item, sizeof (pid2sid_t));
	}
	cache->purge_time = now;
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
		    kidmap_compare_sid_prefix,
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
		    kidmap_compare_sid_prefix;
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
