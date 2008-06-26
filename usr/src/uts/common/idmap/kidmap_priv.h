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
 * This header file contains private definitions.
 */

#ifndef _KIDMAP_PRIV_H
#define	_KIDMAP_PRIV_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/avl.h>

#ifdef	__cplusplus
extern "C" {
#endif


typedef struct idmap_avl_cache {
	avl_tree_t		tree;
	kmutex_t		mutex;
	time_t			purge_time;
} idmap_avl_cache_t;


/*
 * There is a cache for every mapping request because a group SID
 * on Windows can be set in a file owner field and versa-visa.
 * To stop this causing problems on Solaris a SID can map to
 * both a UID and a GID.
 */
typedef struct idmap_cache {
	idmap_avl_cache_t	uidbysid;
	idmap_avl_cache_t	gidbysid;
	idmap_avl_cache_t	pidbysid;
	idmap_avl_cache_t	sidbyuid;
	idmap_avl_cache_t	sidbygid;
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
kidmap_cache_add_uidbysid(idmap_cache_t *cache, const char *sid_prefix,
			uint32_t rid, uid_t uid);

void
kidmap_cache_add_gidbysid(idmap_cache_t *cache, const char *sid_prefix,
			uint32_t rid, gid_t gid);

void
kidmap_cache_add_pidbysid(idmap_cache_t *cache, const char *sid_prefix,
			uint32_t rid, uid_t pid, int is_user);

void
kidmap_cache_add_sidbyuid(idmap_cache_t *cache, const char *sid_prefix,
			uint32_t rid, uid_t uid);

void
kidmap_cache_add_sidbygid(idmap_cache_t *cache, const char *sid_prefix,
			uint32_t rid, gid_t gid);

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
