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
 * This header file contains private definitions.
 */

#ifndef _KIDMAP_PRIV_H
#define	_KIDMAP_PRIV_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/avl.h>

#ifdef	__cplusplus
extern "C" {
#endif

enum	cache_state { 	CACHE_CREATED,
			CACHE_PURGING,
			CACHE_DESTROYING };

typedef struct idmap_avl_cache {
	avl_tree_t		tree;
	krwlock_t		lock;
	kmutex_t		mutex;
	enum cache_state	state;
	time_t			purge_time;
} idmap_avl_cache_t;

typedef struct idmap_cache {
	idmap_avl_cache_t	sid;
	idmap_avl_cache_t	pid;
} idmap_cache_t;


void
kidmap_cache_create(idmap_cache_t *cache);

void
kidmap_cache_delete(idmap_cache_t *cache);

int
kidmap_cache_lookupbypid(idmap_cache_t *cache, const char **sid_prefix,
			uint32_t *rid, uid_t pid, int is_user);

int
kidmap_cache_lookupbysid(idmap_cache_t *cache, const char *sid_prefix,
			uint32_t rid, uid_t *pid, int *is_user);

void
kidmap_cache_addbypid(idmap_cache_t *cache, const char *sid_prefix,
			uint32_t rid, uid_t pid, int is_user, time_t ttl);

void
kidmap_cache_addbysid(idmap_cache_t *cache, const char *sid_prefix,
			uint32_t rid, uid_t pid, int is_user, time_t ttl);

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
