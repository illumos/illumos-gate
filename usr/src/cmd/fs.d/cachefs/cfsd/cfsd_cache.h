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
 *
 *			cache.h
 *
 * Include file for the cache class.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"
/* Copyright (c) 1994 by Sun Microsystems, Inc. */

#ifndef CFSD_CACHE
#define	CFSD_CACHE

typedef struct cfsd_cache_object {
	char			 i_cachedir[MAXPATHLEN]; /* cache directory */
	int			 i_cacheid;		 /* cache id */
	cfsd_fscache_object_t	*i_fscachelist;		 /* list of fscaches */
	int			 i_fscachecount;	 /* # of objs in list */
	mutex_t			 i_lock;		 /* synchro lock */
	int			 i_refcnt;		 /* refs to object */
	int			 i_nextfscacheid;	 /* for fscache ids */
	int			 i_modify;		 /* changes when mod */
	struct cfsd_cache_object	*i_next;	 /* next cache object */
} cfsd_cache_object_t;

cfsd_cache_object_t *cfsd_cache_create(void);
void cfsd_cache_destroy(cfsd_cache_object_t *cache_object_p);

int cache_setup(cfsd_cache_object_t *cache_object_p, const char *cachedirp,
    int cacheid);
void cache_lock(cfsd_cache_object_t *cache_object_p);
void cache_unlock(cfsd_cache_object_t *cache_object_p);

cfsd_fscache_object_t *cache_fscachelist_at(cfsd_cache_object_t *cache_object_p,
    size_t index);
void cache_fscachelist_add(cfsd_cache_object_t *cache_object_p,
    cfsd_fscache_object_t *fscache_object_p);
cfsd_fscache_object_t *cache_fscachelist_find(
    cfsd_cache_object_t *cache_object_p, const char *namep);

#endif /* CFSD_CACHE */
