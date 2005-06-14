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
 * Copyright (c) 1994-2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Methods of the cfsd_cache class.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <thread.h>
#include <synch.h>
#include <locale.h>
#include <sys/utsname.h>
#include <sys/stat.h>
#include <mdbug/mdbug.h>
#include <sys/fs/cachefs_fs.h>
#include <sys/fs/cachefs_dlog.h>
#include <sys/fs/cachefs_ioctl.h>
#include "cfsd.h"
#include "cfsd_kmod.h"
#include "cfsd_maptbl.h"
#include "cfsd_logfile.h"
#include "cfsd_fscache.h"
#include "cfsd_cache.h"

/*
 * -----------------------------------------------------------------
 *			cfsd_cache_create
 *
 * Description:
 * Arguments:
 * Returns:
 * Preconditions:
 */

cfsd_cache_object_t *
cfsd_cache_create(void)
{
	cfsd_cache_object_t *cache_object_p;
	int xx;

	dbug_enter("cfsd_cache_create");

	cache_object_p = cfsd_calloc(sizeof (cfsd_cache_object_t));
	strlcpy(cache_object_p->i_cachedir, gettext("unknown"),
	    sizeof (cache_object_p->i_cachedir));
	cache_object_p->i_refcnt = 0;
	cache_object_p->i_nextfscacheid = 0;
	cache_object_p->i_cacheid = 0;
	cache_object_p->i_modify = 1;
	cache_object_p->i_fscachelist = NULL;
	cache_object_p->i_fscachecount = 0;

	/* initialize the locking mutex */
	xx = mutex_init(&cache_object_p->i_lock, USYNC_THREAD, NULL);

	dbug_assert(xx == 0);
	dbug_leave("cfsd_cache_create");
	return (cache_object_p);
}

/*
 * -----------------------------------------------------------------
 *			cfsd_cache_destroy
 *
 * Description:
 * Arguments:
 * Returns:
 * Preconditions:
 */


void
cfsd_cache_destroy(cfsd_cache_object_t *cache_object_p)
{

	cfsd_fscache_object_t *fscache_object_p;
	cfsd_fscache_object_t *tmp_fscache_object_p;
	int xx;

	dbug_enter("cfsd_cache_destroy");

	/* get rid of any fscache objects */
	fscache_object_p = cache_object_p->i_fscachelist;

	while (fscache_object_p != NULL) {
		tmp_fscache_object_p = fscache_object_p->i_next;
		cfsd_fscache_destroy(fscache_object_p);
		fscache_object_p = tmp_fscache_object_p;
	}

	/* destroy the locking mutex */
	xx = mutex_destroy(&cache_object_p->i_lock);
	dbug_assert(xx == 0);
	cfsd_free(cache_object_p);
	dbug_leave("cfsd_cache_destroy");
}

/*
 * -----------------------------------------------------------------
 *			cache_setup
 *
 * Description:
 *	Performs setup for the cache.
 * Arguments:
 *	cachedirp
 *	cacheid
 * Returns:
 * Preconditions:
 *	precond(cachedirp)
 */

int
cache_setup(cfsd_cache_object_t *cache_object_p, const char *cachedirp,
	int cacheid)
{

	/* XXX either need to prevent multiple calls to this or */
	/*  clean up here. */

	int ret;
	struct stat64 sinfo;
	dbug_enter("cache_setup");

	if ((stat64(cachedirp, &sinfo) == -1) ||
	    (!S_ISDIR(sinfo.st_mode)) ||
	    (*cachedirp != '/')) {
		dbug_print(("info", "%s is not a cache directory", cachedirp));
		ret = 0;
	} else {
		strlcpy(cache_object_p->i_cachedir, cachedirp,
		    sizeof (cache_object_p->i_cachedir));
		ret = 1;
	}

	cache_object_p->i_cacheid = cacheid;
	cache_object_p->i_modify++;

	dbug_leave("cache_setup");
	/* return result */
	return (ret);
}
/*
 * -----------------------------------------------------------------
 *			cache_lock
 *
 * Description:
 * Arguments:
 * Returns:
 * Preconditions:
 */

void
cache_lock(cfsd_cache_object_t *cache_object_p)
{
	dbug_enter("cache_lock");

	mutex_lock(&cache_object_p->i_lock);
	dbug_leave("cache_lock");
}

/*
 * -----------------------------------------------------------------
 *			cache_unlock
 *
 * Description:
 * Arguments:
 * Returns:
 * Preconditions:
 */

void
cache_unlock(cfsd_cache_object_t *cache_object_p)
{
	dbug_enter("cache_unlock");

	mutex_unlock(&cache_object_p->i_lock);
	dbug_leave("cache_unlock");
}
/*
 * -----------------------------------------------------------------
 *			cache_fscachelist_at
 *
 * Description:
 * Arguments:
 *	index
 * Returns:
 *	Returns ...
 * Preconditions:
 */

cfsd_fscache_object_t *
cache_fscachelist_at(cfsd_cache_object_t *cache_object_p, size_t index)
{
	cfsd_fscache_object_t *fscache_object_p;
	int i = 0;

	dbug_enter("cache_fscachelist_at");

	/* find the correct cache object */
	fscache_object_p = cache_object_p->i_fscachelist;

	while ((fscache_object_p != NULL) && (i++ < index)) {
		fscache_object_p = fscache_object_p->i_next;
	}

	dbug_leave("cache_fscachelist_at");
	return (fscache_object_p);
}

/*
 * -----------------------------------------------------------------
 *			cache_fscachelist_add
 *
 * Description:
 * Arguments:
 *	cachep
 * Returns:
 * Preconditions:
 *	precond(fscachep)
 */

void
cache_fscachelist_add(cfsd_cache_object_t *cache_object_p,
	cfsd_fscache_object_t *fscache_object_p)
{
	dbug_enter("cache_fscachelist_add");

	dbug_precond(fscache_object_p);

	fscache_object_p->i_next = cache_object_p->i_fscachelist;
	cache_object_p->i_fscachelist = fscache_object_p;
	cache_object_p->i_modify++;
	cache_object_p->i_fscachecount++;
	dbug_leave("cache_fscachelist_add");
}

/*
 * -----------------------------------------------------------------
 *			cache_fscachelist_find
 *
 * Description:
 * Arguments:
 *	namep
 * Returns:
 *	Returns ...
 * Preconditions:
 *	precond(namep)
 */

cfsd_fscache_object_t *
cache_fscachelist_find(cfsd_cache_object_t *cache_object_p,
	const char *namep)
{
	cfsd_fscache_object_t *fscache_object_p;

	dbug_enter("cache_fscachelist_find");

	dbug_precond(namep);

	/* see if the fscache exists */
	fscache_object_p = cache_object_p->i_fscachelist;

	while ((fscache_object_p != NULL) &&
		strcmp(namep, fscache_object_p->i_name)) {
		fscache_object_p = fscache_object_p->i_next;
	}

	dbug_leave("cache_fscachelist_find");
	return (fscache_object_p);
}
