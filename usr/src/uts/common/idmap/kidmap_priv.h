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
 *
 * Copyright 2023 RackTop Systems, Inc.
 */

/*
 * Windows to Solaris Identity Mapping kernel API
 * This header file contains private definitions.
 */

#ifndef _KIDMAP_PRIV_H
#define	_KIDMAP_PRIV_H

#include <sys/avl.h>

#ifdef	__cplusplus
extern "C" {
#endif

#define	KIDMAP_HASH_SIZE	(1<<8)
#define	KIDMAP_HASH_MASK	(KIDMAP_HASH_SIZE-1)

typedef struct sid2pid {
	avl_node_t	avl_link;
	struct sid2pid	*flink;
	struct sid2pid	*blink;
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
	struct pid2sid	*flink;
	struct pid2sid	*blink;
	const char 	*sid_prefix;
	uint32_t	rid;
	uid_t		pid;
	time_t		ttl;
} pid2sid_t;



typedef struct idmap_sid2pid_cache {
	avl_tree_t		tree;
	kmutex_t		mutex;
	struct sid2pid		head;
	time_t			purge_time;
	int			uid_num;
	int			gid_num;
	int			pid_num;
} idmap_sid2pid_cache_t;


typedef struct idmap_pid2sid_cache {
	avl_tree_t		tree;
	kmutex_t		mutex;
	struct pid2sid		head;
	time_t			purge_time;
} idmap_pid2sid_cache_t;


/*
 * There is a cache for every mapping request because a group SID
 * on Windows can be set in a file owner field and versa-visa.
 * To stop this causing problems on Solaris a SID can map to
 * both a UID and a GID.
 */
typedef struct idmap_cache {
	idmap_sid2pid_cache_t	sid2pid_hash[KIDMAP_HASH_SIZE];
	idmap_pid2sid_cache_t	uid2sid_hash[KIDMAP_HASH_SIZE];
	idmap_pid2sid_cache_t	gid2sid_hash[KIDMAP_HASH_SIZE];
} idmap_cache_t;


void
kidmap_cache_create(idmap_cache_t *cache);

void
kidmap_cache_delete(idmap_cache_t *cache);

void
kidmap_cache_purge(idmap_cache_t *cache);


int
kidmap_cache_lookup_uidbysid(idmap_cache_t *cache, const char *sid_prefix,
			uint32_t rid, uid_t *uid);

int
kidmap_cache_lookup_gidbysid(idmap_cache_t *cache, const char *sid_prefix,
			uint32_t rid, gid_t *gid);

int
kidmap_cache_lookup_pidbysid(idmap_cache_t *cache, const char *sid_prefix,
			uint32_t rid, uid_t *pid, int *is_user);

int
kidmap_cache_lookup_sidbyuid(idmap_cache_t *cache, const char **sid_prefix,
			uint32_t *rid, uid_t uid);

int
kidmap_cache_lookup_sidbygid(idmap_cache_t *cache, const char **sid_prefix,
			uint32_t *rid, gid_t gid);


void
kidmap_cache_add_sid2uid(idmap_cache_t *cache, const char *sid_prefix,
			uint32_t rid, uid_t uid, int direction);

void
kidmap_cache_add_sid2gid(idmap_cache_t *cache, const char *sid_prefix,
			uint32_t rid, gid_t gid, int direction);

void
kidmap_cache_add_sid2pid(idmap_cache_t *cache, const char *sid_prefix,
			uint32_t rid, uid_t pid, int is_user, int direction);
void
kidmap_cache_get_data(idmap_cache_t *cache, size_t *uidbysid, size_t *gidbysid,
			size_t *pidbysid, size_t *sidbyuid, size_t *sidbygid);
int
kidmap_start(void);

int
kidmap_stop(void);

void
kidmap_sid_prefix_store_init(void);

const char *
kidmap_find_sid_prefix(const char *sid_prefix);

#ifdef	__cplusplus
}
#endif

#endif	/* _KIDMAP_PRIV_H */
