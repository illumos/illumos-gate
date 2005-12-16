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
//			all.cc
//
// Methods for the cfsd_all class.
//

#pragma ident	"%Z%%M%	%I%	%E% SMI"
// Copyright (c) 1994 by Sun Microsystems, Inc.

#include <stdio.h>
#include <stdlib.h>
#include <thread.h>
#include <synch.h>
#include <sys/utsname.h>
#include <sys/param.h>
#include <sys/mnttab.h>
#include <sys/vfstab.h>
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
#include "cfsd_all.h"

// -----------------------------------------------------------------
//
//			cfsd_all::cfsd_all
//
// Description:
// Arguments:
// Returns:
// Preconditions:

cfsd_all::cfsd_all()
{
	dbug_enter("cfsd_all::cfsd_all");

	// get the host name
	struct utsname info;
	int xx = uname(&info);

	if (xx == -1) {

		dbug_print("error", ("cannot get host name"));
		i_machname = "unknown";
	} else {
		i_machname = info.nodename;
	}

	// initialize the locking mutex
	xx = mutex_init(&i_lock, USYNC_THREAD, NULL);
	dbug_assert(xx == 0);

	i_nextcacheid = 0;
	i_modify = 1;

	// i_hoardp = NULL;

	dbug_print("info", ("host name is \"%s\"", i_machname));
}

// -----------------------------------------------------------------
//
//			cfsd_all::~cfsd_all
//
// Description:
// Arguments:
// Returns:
// Preconditions:

cfsd_all::~cfsd_all()
{
	dbug_enter("cfsd_all::~cfsd_all");

	// dbug_assert(i_hoardp == NULL);

	// get rid of any cache objects
	i_cachelist.clearAndDestroy();

	// destroy the locking mutex
	int xx = mutex_destroy(&i_lock);
	dbug_assert(xx == 0);
}

// -----------------------------------------------------------------
//
//			cfsd_all::all_machname
//
// Description:
// Arguments:
// Returns:
//	Returns ...
// Preconditions:

const char *
cfsd_all::all_machname()
{
	dbug_enter("cfsd_all::all_machname");

	return (i_machname);
}

// -----------------------------------------------------------------
//
//			cfsd_all::all_lock
//
// Description:
// Arguments:
// Returns:
// Preconditions:

void
cfsd_all::all_lock()
{
	dbug_enter("cfsd_all::all_lock");

	mutex_lock(&i_lock);
}

// -----------------------------------------------------------------
//
//			cfsd_all::all_unlock
//
// Description:
// Arguments:
// Returns:
// Preconditions:

void
cfsd_all::all_unlock()
{
	dbug_enter("cfsd_all::all_unlock");

	mutex_unlock(&i_lock);
}

// -----------------------------------------------------------------
//
//			cfsd_all::all_cachelist_entries
//
// Description:
// Arguments:
// Returns:
//	Returns ...
// Preconditions:

size_t
cfsd_all::all_cachelist_entries()
{
	dbug_enter("cfsd_all::all_cachelist_entries");

	return (i_cachelist.entries());
}

// -----------------------------------------------------------------
//
//			cfsd_all::all_cachelist_at
//
// Description:
// Arguments:
//	index
// Returns:
//	Returns ...
// Preconditions:

cfsd_cache *
cfsd_all::all_cachelist_at(size_t index)
{
	dbug_enter("cfsd_all::all_cachelist_at");

	return (i_cachelist.at(index));
}

// -----------------------------------------------------------------
//
//			cfsd_all::all_cachelist_add
//
// Description:
// Arguments:
//	cachep
// Returns:
// Preconditions:
//	precond(cachep)

void
cfsd_all::all_cachelist_add(cfsd_cache *cachep)
{
	dbug_enter("cfsd_all::all_cachelist_add");

	dbug_precond(cachep);

	i_cachelist.insert(cachep);
	i_modify++;
}

// -----------------------------------------------------------------
//
//			cfsd_all::all_cachelist_find
//
// Description:
// Arguments:
//	namep
// Returns:
//	Returns ...
// Preconditions:
//	precond(namep)

cfsd_cache *
cfsd_all::all_cachelist_find(const char *namep)
{
	dbug_enter("cfsd_all::all_cachelist_find");

	dbug_precond(namep);

	RWTPtrDlistIterator<cfsd_cache> iterator(i_cachelist);
	cfsd_cache *cachep = NULL;

	// see if the cache exists
	while (cachep = iterator()) {
		dbug_assert(cachep);
		if (strcmp(cachep->cache_cachedir(), namep) == 0) {
			break;
		}
	}

	return (cachep);
}

// -----------------------------------------------------------------
//
//			cfsd_all::all_cachefstab_update
//
// Description:
// Arguments:
// Returns:
// Preconditions:

void
cfsd_all::all_cachefstab_update()
{
	dbug_enter("cfsd_all::all_cachefstab_update");

	cfsd_cache *cachep;
	FILE *fout = fopen(CACHEFSTAB, "w");
	if (fout == NULL) {
		dbug_print("error", ("cannot write %s", CACHEFSTAB));
	} else {
		RWTPtrDlistIterator<cfsd_cache> iterator(i_cachelist);
		cachep = NULL;
		while (cachep = iterator()) {
			dbug_assert(cachep);
			fprintf(fout, "%s\n", cachep->cache_cachedir());
		}
		fclose(fout);
	}
}
