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
// ------------------------------------------------------------
//
//			cache.h
//
// Include file for the cache class.
//

#pragma ident	"%Z%%M%	%I%	%E% SMI"
// Copyright (c) 1994 by Sun Microsystems, Inc.

#ifndef CFSD_CACHE
#define	CFSD_CACHE

class cfsd_cache {
private:
	RWCString		 i_cachedir;		// cache directory
	int			 i_cacheid;		// cache id
	RWTPtrDlist<cfsd_fscache> i_fscachelist;	// list of fscaches
	mutex_t			 i_lock;		// synchronizing lock
	int			 i_refcnt;		// refs to object
	int			 i_nextfscacheid;	// for fscache ids
	int			 i_modify;		// changes when modified

public:
	cfsd_cache();
	~cfsd_cache();

	int cache_setup(const char *cachedirp, int cacheid);
	const char *cache_cachedir();
	int cache_cacheid() { return i_cacheid; }

	void cache_lock();
	void cache_unlock();

	int cache_nextfscacheid() { return i_nextfscacheid++; }
	int cache_modify() { return i_modify; }

	void cache_refinc() { i_refcnt++; }
	void cache_refdec() { i_refcnt--; }
	int cache_refcnt() { return i_refcnt; }

	size_t cache_fscachelist_entries();
	cfsd_fscache *cache_fscachelist_at(size_t index);
	void cache_fscachelist_add(cfsd_fscache *fscachep);
	cfsd_fscache *cache_fscachelist_find(const char *namep);

	int operator==(const cfsd_cache &cache) const;
};

#endif /* CFSD_CACHE */
