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
 *			all.h
 *
 * Include file for the cfsd_all class.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"
/* Copyright (c) 1994 by Sun Microsystems, Inc. */

#ifndef CFSD_ALL
#define	CFSD_ALL

/* get define for _SYS_NMLN */
#include <sys/utsname.h>

typedef struct cfsd_all_object {
	char			 i_machname[SYS_NMLN]; /* machine name */
	cfsd_cache_object_t	*i_cachelist;		 /* list of caches */
	int			 i_cachecount;		 /* # of objs on list */
	mutex_t			 i_lock;		 /* synchro lock */
	int			 i_nextcacheid;		 /* for cache ids */
	int			 i_modify;		 /* changed when mod */
#ifdef HOARD_CLASS
	cfsd_hoard		*i_hoardp;		 /* hoarding class */
#endif

} cfsd_all_object_t;

cfsd_all_object_t *cfsd_all_create(void);
void cfsd_all_destroy(cfsd_all_object_t *cfsd_all_object_p);

void all_lock(cfsd_all_object_t *all_object_p);
void all_unlock(cfsd_all_object_t *all_object_p);

cfsd_cache_object_t *all_cachelist_at(cfsd_all_object_t *all_object_p,
    size_t index);
void all_cachelist_add(cfsd_all_object_t *all_object_p,
    cfsd_cache_object_t *cache_object_p);
cfsd_cache_object_t *all_cachelist_find(cfsd_all_object_t *all_object_p,
    const char *namep);

void all_cachefstab_update(cfsd_all_object_t *all_object_p);

#endif /* CFSD_ALL */
