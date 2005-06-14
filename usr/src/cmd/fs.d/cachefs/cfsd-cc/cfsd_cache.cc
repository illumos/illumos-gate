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
// -----------------------------------------------------------------
//
//			cache.cc
//
// Methods of the cfsd_cache class.

#pragma ident	"%Z%%M%	%I%	%E% SMI"
// Copyright (c) 1994 by Sun Microsystems, Inc.

#include <stdio.h>
#include <stdlib.h>
#include <thread.h>
#include <synch.h>
#include <sys/utsname.h>
#include <sys/stat.h>
#include <rw/cstring.h>
#include <rw/regexp.h>
#include <rw/rstream.h>
#include <rw/tpdlist.h>
#include <mdbug-cc/mdbug.h>
#include <sys/fs/cachefs_fs.h>
#include <sys/fs/cachefs_dlog.h>
#include <sys/fs/cachefs_ioctl.h>
#include "cfsd_kmod.h"
#include "cfsd_maptbl.h"
#include "cfsd_logfile.h"
#include "cfsd_fscache.h"
#include "cfsd_cache.h"

// -----------------------------------------------------------------
//
//			cfsd_cache::cfsd_cache
//
// Description:
// Arguments:
// Returns:
// Preconditions:


cfsd_cache::cfsd_cache()
{
	dbug_enter("cfsd_cache::cfsd_cache");
	i_cachedir = "unknown";
	i_refcnt = 0;
	i_nextfscacheid = 0;
	i_cacheid = 0;
	i_modify = 1;

	// initialize the locking mutex
	int xx = mutex_init(&i_lock, USYNC_THREAD, NULL);
	dbug_assert(xx == 0);
}

// -----------------------------------------------------------------
//
//			cfsd_cache::~cfsd_cache
//
// Description:
// Arguments:
// Returns:
// Preconditions:


cfsd_cache::~cfsd_cache()
{
	dbug_enter("cfsd_cache::~cfsd_cache");

	// get rid of any fscache objects
	i_fscachelist.clearAndDestroy();

	// destroy the locking mutex
	int xx = mutex_destroy(&i_lock);
	dbug_assert(xx == 0);
}

// -----------------------------------------------------------------
//
//			cfsd_cache::cache_setup
//
// Description:
//	Performs setup for the cache.
// Arguments:
//	cachedirp
//	cacheid
// Returns:
// Preconditions:
//	precond(cachedirp)

int
cfsd_cache::cache_setup(const char *cachedirp, int cacheid)
{
	dbug_enter("cfsd_cache::cache_setup");

	// XXX either need to prevent multiple calls to this or
	//  clean up here.

	int ret;
	struct stat sinfo;
	if ((stat(cachedirp, &sinfo) == -1) ||
	    (!S_ISDIR(sinfo.st_mode)) ||
	    (*cachedirp != '/')) {
		dbug_print("info", ("%s is not a cache directory", cachedirp));
		ret = 0;
	} else {
		i_cachedir = cachedirp;
		ret = 1;
	}

	i_cacheid = cacheid;
	i_modify++;

	// return result
	return (ret);
}

// -----------------------------------------------------------------
//
//			cfsd_cache::cache_cachedir
//
// Description:
// Arguments:
// Returns:
//	Returns ...
// Preconditions:

const char *
cfsd_cache::cache_cachedir()
{
	dbug_enter("cfsd_cache::cache_cachedir");
	return (i_cachedir);
}

// -----------------------------------------------------------------
//
//			cfsd_cache::cache_lock
//
// Description:
// Arguments:
// Returns:
// Preconditions:

void
cfsd_cache::cache_lock()
{
	dbug_enter("cfsd_cache::cache_lock");

	mutex_lock(&i_lock);
}

// -----------------------------------------------------------------
//
//			cfsd_cache::cache_unlock
//
// Description:
// Arguments:
// Returns:
// Preconditions:

void
cfsd_cache::cache_unlock()
{
	dbug_enter("cfsd_cache::cache_unlock");

	mutex_unlock(&i_lock);
}

// -----------------------------------------------------------------
//
//			cfsd_cache::cache_fscachelist_entries
//
// Description:
// Arguments:
// Returns:
//	Returns ...
// Preconditions:

size_t
cfsd_cache::cache_fscachelist_entries()
{
	dbug_enter("cfsd_cache::cache_fscachelist_entries");

	return (i_fscachelist.entries());
}

// -----------------------------------------------------------------
//
//			cfsd_cache::cache_fscachelist_at
//
// Description:
// Arguments:
//	index
// Returns:
//	Returns ...
// Preconditions:

cfsd_fscache *
cfsd_cache::cache_fscachelist_at(size_t index)
{
	dbug_enter("cfsd_cache::cache_fscachelist_at");

	return (i_fscachelist.at(index));
}

// -----------------------------------------------------------------
//
//			cfsd_cache::cache_fscachelist_add
//
// Description:
// Arguments:
//	cachep
// Returns:
// Preconditions:
//	precond(fscachep)

void
cfsd_cache::cache_fscachelist_add(cfsd_fscache *fscachep)
{
	dbug_enter("cfsd_cache::cache_fscachelist_add");

	dbug_precond(fscachep);

	i_fscachelist.insert(fscachep);
	i_modify++;
}

// -----------------------------------------------------------------
//
//			cfsd_cache::cache_fscachelist_find
//
// Description:
// Arguments:
//	namep
// Returns:
//	Returns ...
// Preconditions:
//	precond(namep)

cfsd_fscache *
cfsd_cache::cache_fscachelist_find(const char *namep)
{
	dbug_enter("cfsd_cache::cache_fscachelist_find");

	dbug_precond(namep);

	RWTPtrDlistIterator<cfsd_fscache> iterator(i_fscachelist);
	cfsd_fscache *fscachep = NULL;

	// see if the fscache exists
	while (fscachep = iterator()) {
		dbug_assert(fscachep);
		if (strcmp(fscachep->fscache_name(), namep) == 0) {
			break;
		}
	}

	return (fscachep);
}

// -----------------------------------------------------------------
//
//			cfsd_cache::operator==
//
// Description:
// Arguments:
//	cachep
// Returns:
//	Returns ...
// Preconditions:

int
cfsd_cache::operator==(const cfsd_cache &cache) const
{
	dbug_enter("cfsd_cache::operator==");
	int xx;
	xx = 0 == strcmp(i_cachedir, cache.i_cachedir);
	return (xx);
}
