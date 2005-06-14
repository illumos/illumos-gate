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
 * Methods for the cfsd_all class.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <thread.h>
#include <synch.h>
#include <locale.h>
#include <errno.h>
#include <sys/utsname.h>
#include <sys/param.h>
#include <sys/mnttab.h>
#include <sys/vfstab.h>
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
#include "cfsd_all.h"

/*
 * ------------------------------------------------------------
 *			cfsd_all_create
 *
 * Description:
 * Arguments:
 * Returns:
 * Preconditions:
 */
cfsd_all_object_t *
cfsd_all_create(void)
{

	/* get the host name */
	struct utsname info;
	cfsd_all_object_t *all_object_p;
	int xx;
	char buffer[MAXPATHLEN];

	dbug_enter("cfsd_all_create");

	all_object_p =
	    (cfsd_all_object_t *)cfsd_calloc(sizeof (cfsd_all_object_t));

	xx = uname(&info);
	if (xx == -1) {
		dbug_print(("error", "cannot get host name"));
		strlcpy(all_object_p->i_machname, gettext("unknown"),
		    sizeof (all_object_p->i_machname));
	} else {
		strlcpy(all_object_p->i_machname, info.nodename,
		    sizeof (all_object_p->i_machname));
	}

	/* initialize the locking mutex */
	xx = mutex_init(&all_object_p->i_lock, USYNC_THREAD, NULL);
	dbug_assert(xx == 0);

	all_object_p->i_nextcacheid = 0;
	all_object_p->i_modify = 1;
	all_object_p->i_cachelist = NULL;
	all_object_p->i_cachecount = 0;

	/* all_object_p->i_hoardp = NULL; */

	snprintf(buffer, sizeof (buffer), gettext("host name is \"%s\""),
	    all_object_p->i_machname);
	dbug_print(("info", buffer));
	dbug_leave("cfsd_all_create");
	return (all_object_p);
}

/*
 * ------------------------------------------------------------
 *			cfsd_all_destroy
 *
 * Description:
 * Arguments:
 * Returns:
 * Preconditions:
 */
void
cfsd_all_destroy(cfsd_all_object_t *all_object_p)
{
	cfsd_cache_object_t *cache_object_p;
	cfsd_cache_object_t *tmp_cache_object_p;
	int xx;

	dbug_enter("cfsd_all_destroy");

	/* dbug_assert(all_object_p->i_hoardp == NULL); */

	/* get rid of any cache objects */
	cache_object_p = all_object_p->i_cachelist;

	while (cache_object_p != NULL) {
		tmp_cache_object_p = cache_object_p->i_next;
		cfsd_cache_destroy(cache_object_p);
		cache_object_p = tmp_cache_object_p;
	}

	/* destroy the locking mutex */
	xx = mutex_destroy(&all_object_p->i_lock);
	dbug_assert(xx == 0);
	cfsd_free(all_object_p);
	dbug_leave("cfsd_all_destroy");
}

/*
 * ------------------------------------------------------------
 *			all_lock
 *
 * Description:
 * Arguments:
 * Returns:
 * Preconditions:
 */
void
all_lock(cfsd_all_object_t *all_object_p)
{
	dbug_enter("all_lock");

	mutex_lock(&all_object_p->i_lock);
	dbug_leave("all_lock");
}

/*
 * ------------------------------------------------------------
 *			all_unlock
 *
 * Description:
 * Arguments:
 * Returns:
 * Preconditions:
 */
void
all_unlock(cfsd_all_object_t *all_object_p)
{
	dbug_enter("all_unlock");

	mutex_unlock(&all_object_p->i_lock);
	dbug_leave("all_unlock");
}

/*
 * ------------------------------------------------------------
 *			all_cachelist_at
 *
 * Description:
 * Arguments:
 *	index
 * Returns:
 *	Returns ...
 * Preconditions:
 */
cfsd_cache_object_t *
all_cachelist_at(cfsd_all_object_t *all_object_p, size_t index)
{
	cfsd_cache_object_t *cache_object_p;
	int i = 0;

	dbug_enter("all_cachelist_at");

	/* find the correct cache object */
	cache_object_p = all_object_p->i_cachelist;

	while ((cache_object_p != NULL) && (i++ < index)) {
		cache_object_p = cache_object_p->i_next;
	}

	dbug_leave("all_cachelist_at");
	return (cache_object_p);
}

/*
 * ------------------------------------------------------------
 *			all_cachelist_add
 *
 * Description:
 * Arguments:
 *	cachep
 * Returns:
 * Preconditions:
 *	precond(cachep)
 */
void
all_cachelist_add(cfsd_all_object_t *all_object_p,
	cfsd_cache_object_t *cache_object_p)
{
	dbug_enter("all_cachelist_add");

	dbug_precond(cache_object_p);

	cache_object_p->i_next = all_object_p->i_cachelist;
	all_object_p->i_cachelist = cache_object_p;
	all_object_p->i_modify++;
	all_object_p->i_cachecount++;
	dbug_leave("all_cachelist_add");
}

/*
 * ------------------------------------------------------------
 *			all_cachelist_find
 *
 * Description:
 * Arguments:
 *	namep
 * Returns:
 *	Returns ...
 * Preconditions:
 *	precond(namep)
 */
cfsd_cache_object_t *
all_cachelist_find(cfsd_all_object_t *all_object_p, const char *namep)
{
	cfsd_cache_object_t *cache_object_p;

	dbug_enter("all_cachelist_find");

	dbug_precond(namep);

	/* find the correct cache object */
	cache_object_p = all_object_p->i_cachelist;

	while ((cache_object_p != NULL) &&
		strcmp(namep, cache_object_p->i_cachedir)) {
		cache_object_p = cache_object_p->i_next;
	}

	dbug_leave("all_cachelist_find");
	return (cache_object_p);
}

/*
 * ------------------------------------------------------------
 *			all_cachefstab_update
 *
 * Description:
 * Arguments:
 * Returns:
 * Preconditions:
 */
void
all_cachefstab_update(cfsd_all_object_t *all_object_p)
{
	cfsd_cache_object_t *cache_object_p;
	FILE *fout;

	dbug_enter("all_cachefstab_update");

	fout = fopen(CACHEFSTAB, "w");
	if (fout == NULL) {
		dbug_print(("error", "cannot write %s", CACHEFSTAB));
	} else {
		cache_object_p = all_object_p->i_cachelist;

		while (cache_object_p != NULL) {
			dbug_assert(cache_object_p);
			fprintf(fout, "%s\n", cache_object_p->i_cachedir);
			cache_object_p = cache_object_p->i_next;
		}
		if (fclose(fout))
			dbug_print(("error", "cannot close %s error %d",
			    CACHEFSTAB, errno));
	}
	dbug_leave("all_cachefstab_update");
}
