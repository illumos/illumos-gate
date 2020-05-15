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
 */

/*
 * Copyright 2020 Nexenta by DDN, Inc. All rights reserved.
 */

/*
 * Windows to Solaris Identity Mapping
 * This module provides the libidmap idmap_cache.
 */


#include <sys/types.h>
#include <sys/avl.h>
#include <assert.h>
#include <pthread.h>
#include <strings.h>
#include <sys/idmap.h>
#include <stddef.h>
#include <stdlib.h>
#include <rpcsvc/idmap_prot.h>
#include "idmap_cache.h"


/*
 * Internal definitions and functions
 */

#define	CACHE_UID_TRIGGER_SIZE	4096
#define	CACHE_GID_TRIGGER_SIZE	2048
#define	CACHE_UID_GID_TRIGGER_SIZE \
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

typedef struct sid2uid_gid {
	avl_node_t		avl_link;
	struct sid2uid_gid	*flink;
	struct sid2uid_gid	*blink;
	const char		*sid_prefix;
	idmap_rid_t		rid;
	uid_t			uid;
	time_t			uid_ttl;
	gid_t			gid;
	time_t			gid_ttl;
	int			is_user;
} sid2uid_gid_t;


typedef struct pid2sid_winname {
	avl_node_t		avl_link;
	struct pid2sid_winname	*flink;
	struct pid2sid_winname	*blink;
	uid_t			pid;
	const char		*sid_prefix;
	idmap_rid_t		rid;
	time_t			sid_ttl;
	const char		*winname;
	const char		*windomain;
	time_t			winname_ttl;
} pid2sid_winname_t;


typedef struct winname2uid_gid {
	avl_node_t		avl_link;
	struct winname2uid_gid	*flink;
	struct winname2uid_gid	*blink;
	const char		*winname;
	const char		*windomain;
	uid_t			uid;
	time_t			uid_ttl;
	gid_t			gid;
	time_t			gid_ttl;
} winname2uid_gid_t;


typedef struct sid2uid_gid_cache {
	avl_tree_t		tree;
	pthread_mutex_t		mutex;
	sid2uid_gid_t		head;
	sid2uid_gid_t		*prev;
	time_t			purge_time;
	int			uid_num;
	int			gid_num;
	int			pid_num;
} sid2uid_gid_cache_t;


typedef struct pid2sid_winname_cache {
	avl_tree_t		tree;
	pthread_mutex_t		mutex;
	pid2sid_winname_t	head;
	pid2sid_winname_t	*prev;
	time_t			purge_time;
	int			sid_num;
	int			winname_num;
} pid2sid_winname_cache_t;



typedef struct winname2uid_gid_cache {
	avl_tree_t		tree;
	pthread_mutex_t		mutex;
	winname2uid_gid_t	head;
	winname2uid_gid_t	*prev;
	time_t			purge_time;
	int			uid_num;
	int			gid_num;
} winname2uid_gid_cache_t;


typedef struct idmap_cache {
	sid2uid_gid_cache_t	sid2uid_gid;
	pid2sid_winname_cache_t	uid2sid_winname;
	pid2sid_winname_cache_t	gid2sid_winname;
	winname2uid_gid_cache_t	winname2uid_gid;
} idmap_cache_t;



typedef int (*avl_comp_fn)(const void*, const void*);

static void
idmap_purge_sid2uid_gid_cache(sid2uid_gid_cache_t *cache, size_t limit);

static void
idmap_purge_pid2sid_winname_cache(pid2sid_winname_cache_t *cache, size_t limit);

static void
idmap_purge_winname2uid_gid_cache(winname2uid_gid_cache_t *avl, size_t limit);

/*
 * Global structures
 */

static idmap_cache_t idmap_cache;




static int
idmap_compare_sid(const sid2uid_gid_t *entry1, const sid2uid_gid_t *entry2)
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
idmap_compare_pid(const pid2sid_winname_t *entry1,
    const pid2sid_winname_t *entry2)
{
	if (entry2->pid > entry1->pid)
		return (1);
	if (entry2->pid < entry1->pid)
		return (-1);
	return (0);
}


static int
idmap_compare_winname(const winname2uid_gid_t *entry1,
    const winname2uid_gid_t *entry2)
{
	int comp;

	comp = strcasecmp(entry2->winname, entry1->winname);
	if (comp == 0) {
		if (entry2->windomain == NULL && entry1->windomain == NULL)
			return (0);
		if (entry1->windomain == NULL)
			return (1);
		if (entry2->windomain == NULL)
			return (-1);

		comp = strcasecmp(entry2->windomain, entry1->windomain);
	}

	if (comp < 0)
		comp = -1;
	else if (comp > 0)
		comp = 1;

	return (comp);
}

/*
 * Routine to update item
 *
 * Returns:	0 Success
 *		-1 Error
 */
static int
update_str(const char **item, const char *str)
{
	char *tmp;

	if (*item != NULL && str != NULL) {
		if (strcmp(*item, str) != 0) {
			if ((tmp = strdup(str)) == NULL)
				return (-1);
			free((char *)*item);
			*item = tmp;
		}
	} else if (str != NULL) {
		/* *item is NULL */
		if ((*item = strdup(str)) == NULL)
			return (-1);
	} else if (*item != NULL) {
		/* str is NULL */
		free((char *)*item);
		*item = NULL;
	}

	return (0);
}

/*
 * The Cache is initialized on loading libidmap.so
 */
#pragma	init(idmap_cache_create)

void
idmap_cache_create(void)
{
	avl_create(&idmap_cache.sid2uid_gid.tree,
	    (avl_comp_fn)idmap_compare_sid, sizeof (sid2uid_gid_t),
	    offsetof(sid2uid_gid_t, avl_link));
	(void) pthread_mutex_init(&idmap_cache.sid2uid_gid.mutex, NULL);
	idmap_cache.sid2uid_gid.head.flink = &idmap_cache.sid2uid_gid.head;
	idmap_cache.sid2uid_gid.head.blink = &idmap_cache.sid2uid_gid.head;
	idmap_cache.sid2uid_gid.prev = NULL;
	idmap_cache.sid2uid_gid.purge_time = 0;
	idmap_cache.sid2uid_gid.uid_num = 0;
	idmap_cache.sid2uid_gid.gid_num = 0;
	idmap_cache.sid2uid_gid.pid_num = 0;

	avl_create(&idmap_cache.uid2sid_winname.tree,
	    (avl_comp_fn)idmap_compare_pid, sizeof (pid2sid_winname_t),
	    offsetof(pid2sid_winname_t, avl_link));
	(void) pthread_mutex_init(&idmap_cache.uid2sid_winname.mutex, NULL);
	idmap_cache.uid2sid_winname.head.flink =
	    &idmap_cache.uid2sid_winname.head;
	idmap_cache.uid2sid_winname.head.blink =
	    &idmap_cache.uid2sid_winname.head;
	idmap_cache.uid2sid_winname.prev = NULL;
	idmap_cache.uid2sid_winname.purge_time = 0;
	idmap_cache.uid2sid_winname.sid_num = 0;
	idmap_cache.uid2sid_winname.winname_num = 0;

	avl_create(&idmap_cache.gid2sid_winname.tree,
	    (avl_comp_fn)idmap_compare_pid, sizeof (pid2sid_winname_t),
	    offsetof(pid2sid_winname_t, avl_link));
	(void) pthread_mutex_init(&idmap_cache.gid2sid_winname.mutex, NULL);
	idmap_cache.gid2sid_winname.head.flink =
	    &idmap_cache.gid2sid_winname.head;
	idmap_cache.gid2sid_winname.head.blink =
	    &idmap_cache.gid2sid_winname.head;
	idmap_cache.gid2sid_winname.prev = NULL;
	idmap_cache.gid2sid_winname.purge_time = 0;
	idmap_cache.gid2sid_winname.sid_num = 0;
	idmap_cache.gid2sid_winname.winname_num = 0;

	avl_create(&idmap_cache.winname2uid_gid.tree,
	    (avl_comp_fn)idmap_compare_winname, sizeof (winname2uid_gid_t),
	    offsetof(winname2uid_gid_t, avl_link));
	(void) pthread_mutex_init(&idmap_cache.winname2uid_gid.mutex, NULL);
	idmap_cache.winname2uid_gid.head.flink =
	    &idmap_cache.winname2uid_gid.head;
	idmap_cache.winname2uid_gid.head.blink =
	    &idmap_cache.winname2uid_gid.head;
	idmap_cache.winname2uid_gid.prev = NULL;
	idmap_cache.winname2uid_gid.purge_time = 0;
	idmap_cache.winname2uid_gid.uid_num = 0;
	idmap_cache.winname2uid_gid.gid_num = 0;
}


void
idmap_cache_purge(void)
{
	sid2uid_gid_t		*sid2uid_gid;
	pid2sid_winname_t	*uid2sid_winname;
	pid2sid_winname_t	*gid2sid_winname;
	winname2uid_gid_t	*winname2uid_gid;
	void			*cookie;

	(void) pthread_mutex_lock(&idmap_cache.sid2uid_gid.mutex);
	cookie = NULL;
	while ((sid2uid_gid = avl_destroy_nodes(
	    &idmap_cache.sid2uid_gid.tree, &cookie)) != NULL) {
		free((char *)sid2uid_gid->sid_prefix);
		free(sid2uid_gid);
	}
	avl_destroy(&idmap_cache.sid2uid_gid.tree);
	avl_create(&idmap_cache.sid2uid_gid.tree,
	    (avl_comp_fn)idmap_compare_sid, sizeof (sid2uid_gid_t),
	    offsetof(sid2uid_gid_t, avl_link));
	idmap_cache.sid2uid_gid.head.flink = &idmap_cache.sid2uid_gid.head;
	idmap_cache.sid2uid_gid.head.blink = &idmap_cache.sid2uid_gid.head;
	idmap_cache.sid2uid_gid.prev = NULL;
	idmap_cache.sid2uid_gid.purge_time = 0;
	idmap_cache.sid2uid_gid.uid_num = 0;
	idmap_cache.sid2uid_gid.gid_num = 0;
	idmap_cache.sid2uid_gid.pid_num = 0;
	(void) pthread_mutex_unlock(&idmap_cache.sid2uid_gid.mutex);


	(void) pthread_mutex_lock(&idmap_cache.uid2sid_winname.mutex);
	cookie = NULL;
	while ((uid2sid_winname = avl_destroy_nodes(
	    &idmap_cache.uid2sid_winname.tree, &cookie)) != NULL) {
		free((char *)uid2sid_winname->sid_prefix);
		free((char *)uid2sid_winname->winname);
		if (uid2sid_winname->windomain != NULL)
			free((char *)uid2sid_winname->windomain);
		free(uid2sid_winname);
	}
	avl_destroy(&idmap_cache.uid2sid_winname.tree);
	avl_create(&idmap_cache.uid2sid_winname.tree,
	    (avl_comp_fn)idmap_compare_pid, sizeof (pid2sid_winname_t),
	    offsetof(pid2sid_winname_t, avl_link));
	idmap_cache.uid2sid_winname.head.flink =
	    &idmap_cache.uid2sid_winname.head;
	idmap_cache.uid2sid_winname.head.blink =
	    &idmap_cache.uid2sid_winname.head;
	idmap_cache.uid2sid_winname.prev = NULL;
	idmap_cache.uid2sid_winname.purge_time = 0;
	idmap_cache.uid2sid_winname.sid_num = 0;
	idmap_cache.uid2sid_winname.winname_num = 0;
	(void) pthread_mutex_unlock(&idmap_cache.uid2sid_winname.mutex);


	(void) pthread_mutex_lock(&idmap_cache.gid2sid_winname.mutex);
	cookie = NULL;
	while ((gid2sid_winname = avl_destroy_nodes(
	    &idmap_cache.gid2sid_winname.tree, &cookie)) != NULL) {
		free((char *)gid2sid_winname->sid_prefix);
		free((char *)gid2sid_winname->winname);
		if (gid2sid_winname->windomain != NULL)
			free((char *)gid2sid_winname->windomain);
		free(gid2sid_winname);
	}
	avl_destroy(&idmap_cache.gid2sid_winname.tree);
	avl_create(&idmap_cache.gid2sid_winname.tree,
	    (avl_comp_fn)idmap_compare_pid, sizeof (pid2sid_winname_t),
	    offsetof(pid2sid_winname_t, avl_link));
	idmap_cache.gid2sid_winname.head.flink =
	    &idmap_cache.gid2sid_winname.head;
	idmap_cache.gid2sid_winname.head.blink =
	    &idmap_cache.gid2sid_winname.head;
	idmap_cache.gid2sid_winname.prev = NULL;
	idmap_cache.gid2sid_winname.purge_time = 0;
	idmap_cache.gid2sid_winname.sid_num = 0;
	idmap_cache.gid2sid_winname.winname_num = 0;
	(void) pthread_mutex_unlock(&idmap_cache.gid2sid_winname.mutex);

	(void) pthread_mutex_lock(&idmap_cache.winname2uid_gid.mutex);
	cookie = NULL;
	while ((winname2uid_gid = avl_destroy_nodes(
	    &idmap_cache.winname2uid_gid.tree, &cookie)) != NULL) {
		free((char *)winname2uid_gid->winname);
		if (winname2uid_gid->windomain)
			free((char *)winname2uid_gid->windomain);
		free(winname2uid_gid);
	}
	avl_destroy(&idmap_cache.winname2uid_gid.tree);
	avl_create(&idmap_cache.winname2uid_gid.tree,
	    (avl_comp_fn)idmap_compare_winname, sizeof (winname2uid_gid_t),
	    offsetof(winname2uid_gid_t, avl_link));
	idmap_cache.winname2uid_gid.head.flink =
	    &idmap_cache.winname2uid_gid.head;
	idmap_cache.winname2uid_gid.head.blink =
	    &idmap_cache.winname2uid_gid.head;
	idmap_cache.winname2uid_gid.prev = NULL;
	idmap_cache.winname2uid_gid.purge_time = 0;
	idmap_cache.winname2uid_gid.uid_num = 0;
	idmap_cache.winname2uid_gid.gid_num = 0;
	(void) pthread_mutex_unlock(&idmap_cache.winname2uid_gid.mutex);

}


void
idmap_cache_get_data(size_t *uidbysid, size_t *gidbysid,
    size_t *pidbysid, size_t *sidbyuid, size_t *sidbygid,
    size_t *winnamebyuid, size_t *winnamebygid,
    size_t *uidbywinname, size_t *gidbywinname)
{
	(void) pthread_mutex_lock(&idmap_cache.sid2uid_gid.mutex);
	*uidbysid = idmap_cache.sid2uid_gid.uid_num;
	*gidbysid = idmap_cache.sid2uid_gid.gid_num;
	*pidbysid = idmap_cache.sid2uid_gid.pid_num;
	(void) pthread_mutex_unlock(&idmap_cache.sid2uid_gid.mutex);

	(void) pthread_mutex_lock(&idmap_cache.uid2sid_winname.mutex);
	*sidbyuid = idmap_cache.uid2sid_winname.sid_num;
	*winnamebyuid = idmap_cache.uid2sid_winname.winname_num;
	(void) pthread_mutex_unlock(&idmap_cache.uid2sid_winname.mutex);

	(void) pthread_mutex_lock(&idmap_cache.gid2sid_winname.mutex);
	*sidbygid = idmap_cache.gid2sid_winname.sid_num;
	*winnamebygid = idmap_cache.gid2sid_winname.winname_num;
	(void) pthread_mutex_unlock(&idmap_cache.gid2sid_winname.mutex);

	(void) pthread_mutex_lock(&idmap_cache.winname2uid_gid.mutex);
	*uidbywinname = idmap_cache.winname2uid_gid.uid_num;
	*gidbywinname = idmap_cache.winname2uid_gid.gid_num;
	(void) pthread_mutex_unlock(&idmap_cache.winname2uid_gid.mutex);
}


idmap_stat
idmap_cache_lookup_uidbysid(const char *sid_prefix,
    idmap_rid_t rid, uid_t *uid)
{
	sid2uid_gid_t	entry;
	sid2uid_gid_t	*result;
	avl_index_t	where;
	int		status = IDMAP_ERR_NOMAPPING;
	time_t		now = time(NULL);

	entry.sid_prefix = sid_prefix;
	entry.rid = rid;

	(void) pthread_mutex_lock(&idmap_cache.sid2uid_gid.mutex);

	result = avl_find(&idmap_cache.sid2uid_gid.tree, &entry, &where);
	if (result != NULL) {
		list_move(&idmap_cache.sid2uid_gid.head, result);
		if (result->uid != UNDEF_UID && result->uid_ttl > now) {
			*uid = result->uid;
			status = IDMAP_SUCCESS;
		}
	}

	(void) pthread_mutex_unlock(&idmap_cache.sid2uid_gid.mutex);

	return (status);
}



idmap_stat
idmap_cache_lookup_gidbysid(const char *sid_prefix,
    idmap_rid_t rid, gid_t *gid)
{
	sid2uid_gid_t	entry;
	sid2uid_gid_t	*result;
	avl_index_t	where;
	int		status = IDMAP_ERR_NOMAPPING;
	time_t		now = time(NULL);

	entry.sid_prefix = sid_prefix;
	entry.rid = rid;

	(void) pthread_mutex_lock(&idmap_cache.sid2uid_gid.mutex);

	result = avl_find(&idmap_cache.sid2uid_gid.tree, &entry, &where);
	if (result != NULL) {
		list_move(&idmap_cache.sid2uid_gid.head, result);
		if (result->gid != UNDEF_GID && result->gid_ttl > now) {
			*gid = result->gid;
			status = IDMAP_SUCCESS;
		}
	}

	(void) pthread_mutex_unlock(&idmap_cache.sid2uid_gid.mutex);

	return (status);
}




idmap_stat
idmap_cache_lookup_pidbysid(const char *sid_prefix,
    idmap_rid_t rid, uid_t *pid, int *is_user)
{
	sid2uid_gid_t	entry;
	sid2uid_gid_t	*result;
	avl_index_t	where;
	int		status = IDMAP_ERR_NOMAPPING;
	time_t		now = time(NULL);

	entry.sid_prefix = sid_prefix;
	entry.rid = rid;

	(void) pthread_mutex_lock(&idmap_cache.sid2uid_gid.mutex);

	result = avl_find(&idmap_cache.sid2uid_gid.tree, &entry, &where);
	if (result != NULL) {
		list_move(&idmap_cache.sid2uid_gid.head, result);
		if (result->is_user != UNDEF_ISUSER) {
			*is_user = result->is_user;
			if (result->is_user && result->uid_ttl > now) {
				*pid = result->uid;
				status = IDMAP_SUCCESS;
			} else if (!result->is_user && result->gid_ttl > now) {
				*pid = result->gid;
				status = IDMAP_SUCCESS;
			}
		}
	}

	(void) pthread_mutex_unlock(&idmap_cache.sid2uid_gid.mutex);

	return (status);
}



idmap_stat
idmap_cache_lookup_sidbyuid(char **sid_prefix,
    idmap_rid_t *rid, uid_t uid)
{
	pid2sid_winname_t	entry;
	pid2sid_winname_t	*result;
	avl_index_t	where;
	int		status = IDMAP_ERR_NOMAPPING;
	time_t		now = time(NULL);

	entry.pid = uid;

	(void) pthread_mutex_lock(&idmap_cache.uid2sid_winname.mutex);

	result = avl_find(&idmap_cache.uid2sid_winname.tree, &entry, &where);
	if (result != NULL) {
		list_move(&idmap_cache.uid2sid_winname.head, result);
		if (result->sid_ttl > now) {
			*rid = result->rid;
			*sid_prefix = strdup(result->sid_prefix);
			if (*sid_prefix != NULL)
				status = IDMAP_SUCCESS;
			else
				status = IDMAP_ERR_MEMORY;
		}
	}

	(void) pthread_mutex_unlock(&idmap_cache.uid2sid_winname.mutex);

	return (status);
}

idmap_stat
idmap_cache_lookup_sidbygid(char **sid_prefix,
    idmap_rid_t *rid, gid_t gid)
{
	pid2sid_winname_t	entry;
	pid2sid_winname_t	*result;
	avl_index_t	where;
	int		status = IDMAP_ERR_NOMAPPING;
	time_t		now = time(NULL);

	entry.pid = gid;

	(void) pthread_mutex_lock(&idmap_cache.gid2sid_winname.mutex);

	result = avl_find(&idmap_cache.gid2sid_winname.tree, &entry, &where);
	if (result != NULL) {
		list_move(&idmap_cache.gid2sid_winname.head, result);
		if (result->sid_ttl > now) {
			*rid = result->rid;
			*sid_prefix = strdup(result->sid_prefix);
			if (*sid_prefix != NULL)
				status = IDMAP_SUCCESS;
			else
				status = IDMAP_ERR_MEMORY;
		}
	}

	(void) pthread_mutex_unlock(&idmap_cache.gid2sid_winname.mutex);

	return (status);
}


idmap_stat
idmap_cache_lookup_winnamebyuid(char **name, char **domain, uid_t uid)
{
	pid2sid_winname_t	entry;
	pid2sid_winname_t	*result;
	avl_index_t	where;
	int		status = IDMAP_ERR_NOMAPPING;
	time_t		now = time(NULL);

	entry.pid = uid;

	(void) pthread_mutex_lock(&idmap_cache.uid2sid_winname.mutex);

	result = avl_find(&idmap_cache.uid2sid_winname.tree, &entry, &where);
	if (result != NULL) {
		list_move(&idmap_cache.uid2sid_winname.head, result);
		if (result->winname_ttl > now) {
			*name = strdup(result->winname);
			if (*name != NULL) {
				if (domain != NULL) {
					if (result->windomain != NULL) {
						*domain =
						    strdup(result->windomain);
						if (*domain != NULL)
							status = IDMAP_SUCCESS;
						else
							status =
							    IDMAP_ERR_MEMORY;
					} else {
						*domain = NULL;
						status = IDMAP_SUCCESS;
					}
				} else
					status = IDMAP_SUCCESS;
			} else
				status = IDMAP_ERR_MEMORY;
		}
	}

	(void) pthread_mutex_unlock(&idmap_cache.uid2sid_winname.mutex);

	return (status);
}


idmap_stat
idmap_cache_lookup_winnamebygid(char **name, char **domain, gid_t gid)
{
	pid2sid_winname_t	entry;
	pid2sid_winname_t	*result;
	avl_index_t	where;
	int		status = IDMAP_ERR_NOMAPPING;
	time_t		now = time(NULL);

	entry.pid = gid;

	(void) pthread_mutex_lock(&idmap_cache.gid2sid_winname.mutex);

	result = avl_find(&idmap_cache.gid2sid_winname.tree, &entry, &where);
	if (result != NULL) {
		list_move(&idmap_cache.gid2sid_winname.head, result);
		if (result->winname_ttl > now) {
			*name = strdup(result->winname);
			if (*name != NULL) {
				if (domain != NULL) {
					if (result->windomain != NULL) {
						*domain =
						    strdup(result->windomain);
						if (*domain != NULL)
							status = IDMAP_SUCCESS;
						else
							status =
							    IDMAP_ERR_MEMORY;
					} else {
						*domain = NULL;
						status = IDMAP_SUCCESS;
					}
				} else
					status = IDMAP_SUCCESS;
			} else
				status = IDMAP_ERR_MEMORY;
		}
	}

	(void) pthread_mutex_unlock(&idmap_cache.gid2sid_winname.mutex);

	return (status);
}


idmap_stat
idmap_cache_lookup_uidbywinname(const char *name, const char *domain,
    uid_t *uid)
{
	winname2uid_gid_t	entry;
	winname2uid_gid_t	*result;
	avl_index_t	where;
	int		status = IDMAP_ERR_NOMAPPING;
	time_t		now = time(NULL);

	entry.winname = name;
	entry.windomain = domain;

	(void) pthread_mutex_lock(&idmap_cache.winname2uid_gid.mutex);

	result = avl_find(&idmap_cache.winname2uid_gid.tree, &entry, &where);
	if (result != NULL) {
		list_move(&idmap_cache.winname2uid_gid.head, result);
		if (result->uid != UNDEF_UID && result->uid_ttl > now) {
			*uid = result->uid;
			status = IDMAP_SUCCESS;
		}
	}

	(void) pthread_mutex_unlock(&idmap_cache.winname2uid_gid.mutex);

	return (status);
}


idmap_stat
idmap_cache_lookup_gidbywinname(const char *name, const char *domain,
    gid_t *gid)
{
	winname2uid_gid_t	entry;
	winname2uid_gid_t	*result;
	avl_index_t	where;
	int		status = IDMAP_ERR_NOMAPPING;
	time_t		now = time(NULL);

	entry.winname = name;
	entry.windomain = domain;

	(void) pthread_mutex_lock(&idmap_cache.winname2uid_gid.mutex);

	result = avl_find(&idmap_cache.winname2uid_gid.tree, &entry, &where);
	if (result != NULL) {
		list_move(&idmap_cache.winname2uid_gid.head, result);
		if (result->gid != UNDEF_GID && result->gid_ttl > now) {
			*gid = result->gid;
			status = IDMAP_SUCCESS;
		}
	}

	(void) pthread_mutex_unlock(&idmap_cache.winname2uid_gid.mutex);

	return (status);
}


void
idmap_cache_add_sid2uid(const char *sid_prefix,
    idmap_rid_t rid, uid_t uid, int direction)
{
	avl_index_t	where;
	time_t		ttl = CACHE_TTL + time(NULL);


	if (direction == IDMAP_DIRECTION_BI ||
	    direction == IDMAP_DIRECTION_W2U) {
		sid2uid_gid_t	find;
		sid2uid_gid_t	*result;
		sid2uid_gid_t	*new;

		find.sid_prefix = sid_prefix;
		find.rid = rid;

		(void) pthread_mutex_lock(&idmap_cache.sid2uid_gid.mutex);
		result = avl_find(&idmap_cache.sid2uid_gid.tree, &find, &where);

		if (result) {
			if (result->uid_ttl == 0)
				idmap_cache.sid2uid_gid.uid_num++;
			result->uid = uid;
			result->uid_ttl = ttl;
		} else {
			new = malloc(sizeof (sid2uid_gid_t));
			if (new == NULL)
				goto exit_sid2uid_gid;
			new->sid_prefix = strdup(sid_prefix);
			if (new->sid_prefix == NULL) {
				free(new);
				goto exit_sid2uid_gid;
			}
			new->rid = rid;
			new->uid = uid;
			new->uid_ttl = ttl;
			new->gid = UNDEF_GID;
			new->gid_ttl = 0;
			new->is_user = UNDEF_ISUSER; /* Unknown */
			idmap_cache.sid2uid_gid.uid_num++;

			list_insert(&idmap_cache.sid2uid_gid.head, new);
			avl_insert(&idmap_cache.sid2uid_gid.tree, new, where);
		}
		if ((avl_numnodes(&idmap_cache.sid2uid_gid.tree) >
		    CACHE_UID_GID_TRIGGER_SIZE) &&
		    (idmap_cache.sid2uid_gid.purge_time + CACHE_PURGE_INTERVAL <
		    time(NULL)))
			idmap_purge_sid2uid_gid_cache(&idmap_cache.sid2uid_gid,
			    CACHE_UID_GID_TRIGGER_SIZE);

exit_sid2uid_gid:
		(void) pthread_mutex_unlock(&idmap_cache.sid2uid_gid.mutex);
	}

	if (direction == IDMAP_DIRECTION_BI ||
	    direction == IDMAP_DIRECTION_U2W) {
		pid2sid_winname_t	find;
		pid2sid_winname_t	*result;
		pid2sid_winname_t	*new;

		find.pid = uid;

		(void) pthread_mutex_lock(&idmap_cache.uid2sid_winname.mutex);
		result = avl_find(&idmap_cache.uid2sid_winname.tree, &find,
		    &where);

		if (result) {
			if (update_str(&result->sid_prefix, sid_prefix) != 0)
				goto exit_pid2sid_winname;
			if (result->sid_ttl == 0)
					idmap_cache.uid2sid_winname.sid_num++;
			result->rid = rid;
			result->sid_ttl = ttl;
		} else {
			new = malloc(sizeof (pid2sid_winname_t));
			if (new == NULL)
				goto exit_pid2sid_winname;
			new->pid = uid;
			new->sid_prefix = strdup(sid_prefix);
			if (new->sid_prefix == NULL) {
				free(new);
				goto exit_pid2sid_winname;
			}
			new->rid = rid;
			new->sid_ttl = ttl;
			new->winname = NULL;
			new->windomain = NULL;
			new->winname_ttl = 0;
			idmap_cache.uid2sid_winname.sid_num ++;

			list_insert(&idmap_cache.uid2sid_winname.head, new);
			avl_insert(&idmap_cache.uid2sid_winname.tree, new,
			    where);
		}
		if ((avl_numnodes(&idmap_cache.uid2sid_winname.tree) >
		    CACHE_UID_TRIGGER_SIZE) &&
		    (idmap_cache.uid2sid_winname.purge_time +
		    CACHE_PURGE_INTERVAL < time(NULL)))
			idmap_purge_pid2sid_winname_cache(
			    &idmap_cache.uid2sid_winname,
			    CACHE_UID_TRIGGER_SIZE);


exit_pid2sid_winname:
		(void) pthread_mutex_unlock(&idmap_cache.uid2sid_winname.mutex);
	}
}



void
idmap_cache_add_sid2gid(const char *sid_prefix,
    idmap_rid_t rid, gid_t gid, int direction)
{
	avl_index_t	where;
	time_t		ttl = CACHE_TTL + time(NULL);


	if (direction == IDMAP_DIRECTION_BI ||
	    direction == IDMAP_DIRECTION_W2U) {
		sid2uid_gid_t	find;
		sid2uid_gid_t	*result;
		sid2uid_gid_t	*new;

		find.sid_prefix = sid_prefix;
		find.rid = rid;

		(void) pthread_mutex_lock(&idmap_cache.sid2uid_gid.mutex);
		result = avl_find(&idmap_cache.sid2uid_gid.tree, &find, &where);

		if (result) {
			if (result->gid_ttl == 0)
				idmap_cache.sid2uid_gid.gid_num++;
			result->gid = gid;
			result->gid_ttl = ttl;
		} else {
			new = malloc(sizeof (sid2uid_gid_t));
			if (new == NULL)
				goto exit_sid2uid_gid;
			new->sid_prefix = strdup(sid_prefix);
			if (new->sid_prefix == NULL) {
				free(new);
				goto exit_sid2uid_gid;
			}
			new->rid = rid;
			new->uid = UNDEF_UID;
			new->uid_ttl = 0;
			new->gid = gid;
			new->gid_ttl = ttl;
			new->is_user = UNDEF_ISUSER; /* Unknown */
			idmap_cache.sid2uid_gid.gid_num++;

			list_insert(&idmap_cache.sid2uid_gid.head, new);
			avl_insert(&idmap_cache.sid2uid_gid.tree, new, where);
		}
		if ((avl_numnodes(&idmap_cache.sid2uid_gid.tree) >
		    CACHE_UID_GID_TRIGGER_SIZE) &&
		    (idmap_cache.sid2uid_gid.purge_time + CACHE_PURGE_INTERVAL <
		    time(NULL)))
			idmap_purge_sid2uid_gid_cache(&idmap_cache.sid2uid_gid,
			    CACHE_UID_GID_TRIGGER_SIZE);

exit_sid2uid_gid:
		(void) pthread_mutex_unlock(&idmap_cache.sid2uid_gid.mutex);
	}

	if (direction == IDMAP_DIRECTION_BI ||
	    direction == IDMAP_DIRECTION_U2W) {
		pid2sid_winname_t	find;
		pid2sid_winname_t	*result;
		pid2sid_winname_t	*new;

		find.pid = gid;

		(void) pthread_mutex_lock(&idmap_cache.gid2sid_winname.mutex);
		result = avl_find(&idmap_cache.gid2sid_winname.tree, &find,
		    &where);

		if (result) {
			if (update_str(&result->sid_prefix, sid_prefix) != 0)
				goto  exit_gid2sid_winname;
			if (result->sid_ttl == 0)
				idmap_cache.gid2sid_winname.sid_num++;
			result->rid = rid;
			result->sid_ttl = ttl;
		} else {
			new = malloc(sizeof (pid2sid_winname_t));
			if (new == NULL)
				goto exit_gid2sid_winname;
			new->sid_prefix = strdup(sid_prefix);
			if (new->sid_prefix == NULL) {
				free(new);
				goto exit_gid2sid_winname;
			}
			new->rid = rid;
			new->pid = gid;
			new->sid_ttl = ttl;
			new->winname = NULL;
			new->windomain = NULL;
			new->winname_ttl = 0;
			idmap_cache.gid2sid_winname.sid_num++;

			list_insert(&idmap_cache.gid2sid_winname.head, new);
			avl_insert(&idmap_cache.gid2sid_winname.tree, new,
			    where);
		}
		if ((avl_numnodes(&idmap_cache.gid2sid_winname.tree) >
		    CACHE_GID_TRIGGER_SIZE) &&
		    (idmap_cache.gid2sid_winname.purge_time +
		    CACHE_PURGE_INTERVAL < time(NULL)))
			idmap_purge_pid2sid_winname_cache(
			    &idmap_cache.gid2sid_winname,
			    CACHE_GID_TRIGGER_SIZE);

exit_gid2sid_winname:
		(void) pthread_mutex_unlock(&idmap_cache.gid2sid_winname.mutex);
	}
}


void
idmap_cache_add_sid2pid(const char *sid_prefix,
    idmap_rid_t rid, uid_t pid, int is_user, int direction)
{
	avl_index_t	where;
	time_t		ttl = CACHE_TTL + time(NULL);


	if (direction == IDMAP_DIRECTION_BI ||
	    direction == IDMAP_DIRECTION_W2U) {
		sid2uid_gid_t	find;
		sid2uid_gid_t	*result;
		sid2uid_gid_t	*new;

		find.sid_prefix = sid_prefix;
		find.rid = rid;

		(void) pthread_mutex_lock(&idmap_cache.sid2uid_gid.mutex);
		result = avl_find(&idmap_cache.sid2uid_gid.tree, &find, &where);

		if (result) {
			if (result->is_user == UNDEF_ISUSER)
				idmap_cache.sid2uid_gid.pid_num++;
			result->is_user = is_user;
			if (is_user) {
				if (result->uid_ttl == 0)
					idmap_cache.sid2uid_gid.uid_num++;
				result->uid = pid;
				result->uid_ttl = ttl;
			} else {
				if (result->gid_ttl == 0)
					idmap_cache.sid2uid_gid.gid_num++;
				result->gid = pid;
				result->gid_ttl = ttl;
			}
		} else {
			new = malloc(sizeof (sid2uid_gid_t));
			if (new == NULL)
				goto exit_sid2uid_gid;
			new->sid_prefix = strdup(sid_prefix);
			if (new->sid_prefix == NULL) {
				free(new);
				goto exit_sid2uid_gid;
			}
			new->rid = rid;
			new->is_user = is_user;
			if (is_user) {
				new->uid = pid;
				new->uid_ttl = ttl;
				new->gid = UNDEF_GID;
				new->gid_ttl = 0;
				idmap_cache.sid2uid_gid.uid_num++;
			} else {
				new->uid = UNDEF_UID;
				new->uid_ttl = 0;
				new->gid = pid;
				new->gid_ttl = ttl;
				idmap_cache.sid2uid_gid.gid_num++;
			}
			idmap_cache.sid2uid_gid.pid_num++;

			list_insert(&idmap_cache.sid2uid_gid.head, new);
			avl_insert(&idmap_cache.sid2uid_gid.tree, new, where);
		}
		if ((avl_numnodes(&idmap_cache.sid2uid_gid.tree) >
		    CACHE_UID_GID_TRIGGER_SIZE) &&
		    (idmap_cache.sid2uid_gid.purge_time + CACHE_PURGE_INTERVAL <
		    time(NULL)))
			idmap_purge_sid2uid_gid_cache(&idmap_cache.sid2uid_gid,
			    CACHE_UID_GID_TRIGGER_SIZE);

exit_sid2uid_gid:
		(void) pthread_mutex_unlock(&idmap_cache.sid2uid_gid.mutex);
	}

	if (direction == IDMAP_DIRECTION_BI ||
	    direction == IDMAP_DIRECTION_U2W) {
		pid2sid_winname_t	find;
		pid2sid_winname_t	*result;
		pid2sid_winname_t	*new;

		find.pid = pid;
		if (is_user) {
			(void) pthread_mutex_lock(
			    &idmap_cache.uid2sid_winname.mutex);
			result = avl_find(&idmap_cache.uid2sid_winname.tree,
			    &find, &where);

			if (result) {
				if (update_str(&result->sid_prefix, sid_prefix)
				    != 0)
					goto exit_uid2sid_winname;
				if (result->sid_ttl == 0)
					idmap_cache.uid2sid_winname.sid_num++;
				result->rid = rid;
				result->sid_ttl = ttl;
			} else {
				new = malloc(sizeof (pid2sid_winname_t));
				if (new == NULL)
					goto exit_uid2sid_winname;
				new->sid_prefix = strdup(sid_prefix);
				if (new->sid_prefix == NULL) {
					free(new);
					goto exit_uid2sid_winname;
				}
				new->rid = rid;
				new->pid = pid;
				new->sid_ttl = ttl;
				new->winname = NULL;
				new->windomain = NULL;
				new->winname_ttl = 0;
				idmap_cache.uid2sid_winname.sid_num++;

				list_insert(&idmap_cache.uid2sid_winname.head,
				    new);
				avl_insert(&idmap_cache.uid2sid_winname.tree,
				    new, where);
			}
			if ((avl_numnodes(&idmap_cache.uid2sid_winname.tree) >
			    CACHE_UID_TRIGGER_SIZE) &&
			    (idmap_cache.uid2sid_winname.purge_time +
			    CACHE_PURGE_INTERVAL < time(NULL)))
				idmap_purge_pid2sid_winname_cache(
				    &idmap_cache.uid2sid_winname,
				    CACHE_UID_TRIGGER_SIZE);

exit_uid2sid_winname:
			(void) pthread_mutex_unlock(
			    &idmap_cache.uid2sid_winname.mutex);
		} else {
			(void) pthread_mutex_lock(
			    &idmap_cache.gid2sid_winname.mutex);
			result = avl_find(&idmap_cache.gid2sid_winname.tree,
			    &find, &where);

			if (result) {
				if (update_str(&result->sid_prefix, sid_prefix)
				    != 0)
					goto exit_gid2sid_winname;
				if (result->sid_ttl == 0)
					idmap_cache.gid2sid_winname.sid_num++;
				result->rid = rid;
				result->sid_ttl = ttl;
			} else {
				new = malloc(sizeof (pid2sid_winname_t));
				if (new == NULL)
					goto exit_gid2sid_winname;
				new->sid_prefix = strdup(sid_prefix);
				if (new->sid_prefix == NULL) {
					free(new);
					goto exit_gid2sid_winname;
				}
				new->rid = rid;
				new->pid = pid;
				new->sid_ttl = ttl;
				new->winname = NULL;
				new->windomain = NULL;
				new->winname_ttl = 0;
				idmap_cache.gid2sid_winname.sid_num++;

				list_insert(&idmap_cache.gid2sid_winname.head,
				    new);
				avl_insert(&idmap_cache.gid2sid_winname.tree,
				    new, where);
			}
			if ((avl_numnodes(&idmap_cache.gid2sid_winname.tree) >
			    CACHE_GID_TRIGGER_SIZE) &&
			    (idmap_cache.gid2sid_winname.purge_time +
			    CACHE_PURGE_INTERVAL < time(NULL)))
				idmap_purge_pid2sid_winname_cache(
				    &idmap_cache.gid2sid_winname,
				    CACHE_GID_TRIGGER_SIZE);
exit_gid2sid_winname:
			(void) pthread_mutex_unlock(
			    &idmap_cache.gid2sid_winname.mutex);
		}
	}
}



void
idmap_cache_add_winname2uid(const char *name, const char *domain, uid_t uid,
    int direction)
{
	avl_index_t	where;
	time_t		ttl = CACHE_TTL + time(NULL);


	if (direction == IDMAP_DIRECTION_BI ||
	    direction == IDMAP_DIRECTION_W2U) {
		winname2uid_gid_t	find;
		winname2uid_gid_t	*result;
		winname2uid_gid_t	*new;

		find.winname = name;
		find.windomain = domain;

		(void) pthread_mutex_lock(&idmap_cache.winname2uid_gid.mutex);
		result = avl_find(&idmap_cache.winname2uid_gid.tree, &find,
		    &where);

		if (result) {
			if (result->uid_ttl == 0)
				idmap_cache.winname2uid_gid.uid_num++;
			result->uid = uid;
			result->uid_ttl = ttl;
		} else {
			new = malloc(sizeof (winname2uid_gid_t));
			if (new == NULL)
				goto exit_winname2uid_gid;
			new->winname = strdup(name);
			if (new->winname == NULL) {
				free(new);
				goto exit_winname2uid_gid;
			}
			if (domain != NULL) {
				new->windomain = strdup(domain);
				if (new->winname == NULL) {
					free((char *)new->winname);
					free(new);
					goto exit_winname2uid_gid;
				}
			} else
				new->windomain = NULL;
			new->uid = uid;
			new->uid_ttl = ttl;
			new->gid = UNDEF_GID;
			new->gid_ttl = 0;
			idmap_cache.winname2uid_gid.uid_num++;

			list_insert(&idmap_cache.winname2uid_gid.head, new);
			avl_insert(&idmap_cache.winname2uid_gid.tree, new,
			    where);
		}
		if ((avl_numnodes(&idmap_cache.winname2uid_gid.tree) >
		    CACHE_UID_GID_TRIGGER_SIZE) &&
		    (idmap_cache.winname2uid_gid.purge_time +
		    CACHE_PURGE_INTERVAL < time(NULL)))
			idmap_purge_winname2uid_gid_cache(
			    &idmap_cache.winname2uid_gid,
			    CACHE_UID_GID_TRIGGER_SIZE);
exit_winname2uid_gid:
		(void) pthread_mutex_unlock(&idmap_cache.winname2uid_gid.mutex);
	}

	if (direction == IDMAP_DIRECTION_BI ||
	    direction == IDMAP_DIRECTION_U2W) {
		pid2sid_winname_t	find;
		pid2sid_winname_t	*result;
		pid2sid_winname_t	*new;

		find.pid = uid;

		(void) pthread_mutex_lock(&idmap_cache.uid2sid_winname.mutex);
		result = avl_find(&idmap_cache.uid2sid_winname.tree, &find,
		    &where);

		if (result) {
			if (update_str(&result->winname, name) != 0)
				goto exit_uid2sid_winname;
			if (update_str(&result->windomain, domain) != 0)
				goto exit_uid2sid_winname;
			if (result->winname_ttl == 0)
				idmap_cache.uid2sid_winname.winname_num++;
			result->winname_ttl = ttl;
		} else {
			new = malloc(sizeof (pid2sid_winname_t));
			if (new == NULL)
				goto exit_uid2sid_winname;
			new->pid = uid;
			new->winname = strdup(name);
			if (new->winname == NULL) {
				free(new);
				goto exit_uid2sid_winname;
			}
			if (domain != NULL) {
				new->windomain = strdup(domain);
				if (new->windomain == NULL) {
					free((char *)new->winname);
					free(new);
					goto exit_uid2sid_winname;
				}
			} else
				new->windomain = NULL;
			new->winname_ttl = ttl;
			new->sid_prefix = NULL;
			new->rid = 0;
			new->sid_ttl = 0;
			idmap_cache.uid2sid_winname.winname_num ++;

			list_insert(&idmap_cache.uid2sid_winname.head, new);
			avl_insert(&idmap_cache.uid2sid_winname.tree, new,
			    where);
		}
		if ((avl_numnodes(&idmap_cache.uid2sid_winname.tree) >
		    CACHE_UID_TRIGGER_SIZE) &&
		    (idmap_cache.uid2sid_winname.purge_time +
		    CACHE_PURGE_INTERVAL < time(NULL)))
			idmap_purge_pid2sid_winname_cache(
			    &idmap_cache.uid2sid_winname,
			    CACHE_UID_TRIGGER_SIZE);
exit_uid2sid_winname:
		(void) pthread_mutex_unlock(&idmap_cache.uid2sid_winname.mutex);
	}
}





void
idmap_cache_add_winname2gid(const char *name, const char *domain, gid_t gid,
    int direction)
{
	avl_index_t	where;
	time_t		ttl = CACHE_TTL + time(NULL);


	if (direction == IDMAP_DIRECTION_BI ||
	    direction == IDMAP_DIRECTION_W2U) {
		winname2uid_gid_t	find;
		winname2uid_gid_t	*result;
		winname2uid_gid_t	*new;

		find.winname = name;
		find.windomain = domain;

		(void) pthread_mutex_lock(&idmap_cache.winname2uid_gid.mutex);
		result = avl_find(&idmap_cache.winname2uid_gid.tree, &find,
		    &where);

		if (result) {
			if (result->uid_ttl == 0)
				idmap_cache.winname2uid_gid.gid_num++;
			result->gid = gid;
			result->gid_ttl = ttl;
		} else {
			new = malloc(sizeof (winname2uid_gid_t));
			if (new == NULL)
				goto exit_winname2uid_gid;
			new->winname = strdup(name);
			if (new->winname == NULL) {
				free(new);
				goto exit_winname2uid_gid;
			}
			if (domain != NULL) {
				new->windomain = strdup(domain);
				if (new->windomain == NULL) {
					free((char *)new->winname);
					free(new);
					goto exit_winname2uid_gid;
				}
			}
			else
				new->windomain = NULL;
			new->uid = UNDEF_UID;
			new->uid_ttl = 0;
			new->gid = gid;
			new->gid_ttl = ttl;
			idmap_cache.winname2uid_gid.gid_num++;

			list_insert(&idmap_cache.winname2uid_gid.head, new);
			avl_insert(&idmap_cache.winname2uid_gid.tree, new,
			    where);
		}
		if ((avl_numnodes(&idmap_cache.winname2uid_gid.tree) >
		    CACHE_UID_GID_TRIGGER_SIZE) &&
		    (idmap_cache.winname2uid_gid.purge_time +
		    CACHE_PURGE_INTERVAL < time(NULL)))
			idmap_purge_winname2uid_gid_cache(
			    &idmap_cache.winname2uid_gid,
			    CACHE_UID_GID_TRIGGER_SIZE);
exit_winname2uid_gid:
		(void) pthread_mutex_unlock(&idmap_cache.winname2uid_gid.mutex);
	}

	if (direction == IDMAP_DIRECTION_BI ||
	    direction == IDMAP_DIRECTION_U2W) {
		pid2sid_winname_t	find;
		pid2sid_winname_t	*result;
		pid2sid_winname_t	*new;

		find.pid = gid;

		(void) pthread_mutex_lock(&idmap_cache.gid2sid_winname.mutex);
		result = avl_find(&idmap_cache.gid2sid_winname.tree, &find,
		    &where);

		if (result) {
			if (update_str(&result->winname, name) != 0)
				goto exit_gid2sid_winname;
			if (update_str(&result->windomain, domain) != 0)
				goto exit_gid2sid_winname;
			if (result->winname_ttl == 0)
				idmap_cache.gid2sid_winname.winname_num++;
			result->winname_ttl = ttl;
		} else {
			new = malloc(sizeof (pid2sid_winname_t));
			if (new == NULL)
				goto exit_gid2sid_winname;
			new->pid = gid;
			new->winname = strdup(name);
			if (new->winname == NULL) {
				free(new);
				goto exit_gid2sid_winname;
			}
			if (domain != NULL) {
				new->windomain = strdup(domain);
				if (new->windomain == NULL) {
					free((char *)new->winname);
					free(new);
					goto exit_gid2sid_winname;
				}
			}
			else
				new->windomain = NULL;
			new->winname_ttl = ttl;
			new->sid_prefix = NULL;
			new->rid = 0;
			new->sid_ttl = 0;
			idmap_cache.gid2sid_winname.winname_num ++;

			list_insert(&idmap_cache.gid2sid_winname.head, new);
			avl_insert(&idmap_cache.gid2sid_winname.tree, new,
			    where);
		}
		if ((avl_numnodes(&idmap_cache.gid2sid_winname.tree) >
		    CACHE_UID_TRIGGER_SIZE) &&
		    (idmap_cache.gid2sid_winname.purge_time +
		    CACHE_PURGE_INTERVAL < time(NULL)))
			idmap_purge_pid2sid_winname_cache(
			    &idmap_cache.gid2sid_winname,
			    CACHE_UID_TRIGGER_SIZE);
exit_gid2sid_winname:
		(void) pthread_mutex_unlock(&idmap_cache.gid2sid_winname.mutex);
	}
}


static void
idmap_purge_sid2uid_gid_cache(sid2uid_gid_cache_t *cache, size_t limit)
{
	time_t		now = time(NULL);
	sid2uid_gid_t	*item;

	while (avl_numnodes(&cache->tree) > limit) {
		/* Remove least recently used */
		item = cache->head.blink;
		list_remove(item);
		avl_remove(&cache->tree, item);
		if (item->uid_ttl != 0)
			cache->uid_num--;
		if (item->gid_ttl != 0)
			cache->gid_num--;
		if (item->is_user != UNDEF_ISUSER)
			cache->pid_num--;

		if (item->sid_prefix)
			free((char *)item->sid_prefix);
		free(item);
	}
	cache->purge_time = now;
}


static void
idmap_purge_winname2uid_gid_cache(winname2uid_gid_cache_t *cache, size_t limit)
{
	time_t		now = time(NULL);
	winname2uid_gid_t	*item;

	while (avl_numnodes(&cache->tree) > limit) {
		/* Remove least recently used */
		item = cache->head.blink;
		list_remove(item);
		avl_remove(&cache->tree, item);
		if (item->uid_ttl != 0)
			cache->uid_num--;
		if (item->gid_ttl != 0)
			cache->gid_num--;

		if (item->winname)
			free((char *)item->winname);
		if (item->windomain)
			free((char *)item->windomain);
		free(item);
	}
	cache->purge_time = now;
}


static void
idmap_purge_pid2sid_winname_cache(pid2sid_winname_cache_t *cache, size_t limit)
{
	time_t		now = time(NULL);
	pid2sid_winname_t	*item;

	while (avl_numnodes(&cache->tree) > limit) {
		/* Remove least recently used */
		item = cache->head.blink;
		list_remove(item);
		avl_remove(&cache->tree, item);
		if (item->winname_ttl != 0)
			cache->winname_num--;
		if (item->sid_ttl != 0)
			cache->sid_num--;

		if (item->winname)
			free((char *)item->winname);
		if (item->windomain)
			free((char *)item->windomain);
		if (item->sid_prefix)
			free((char *)item->sid_prefix);
		free(item);
	}
	cache->purge_time = now;
}
