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
//			cfsd_svc.cc
//
// RPC service routines.

#pragma ident	"%Z%%M%	%I%	%E% SMI"
// Copyright (c) 1994 by Sun Microsystems, Inc.

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <rpc/rpc.h>
#include <rpc/pmap_clnt.h> /* for pmap_unset */
#include <string.h> /* strcmp */
#include <signal.h>
#include <sysent.h> /* getdtablesize, open */
#include <unistd.h> /* setsid */
#include <sys/types.h>
#include <time.h>
#include <memory.h>
#include <stropts.h>
#include <netconfig.h>
#include <sys/resource.h> /* rlimit */
#include <rw/cstring.h>
#include <rw/regexp.h>
#include <rw/rstream.h>
#include <rw/tpdlist.h>
#include <thread.h>
#include <synch.h>
#include <mdbug-cc/mdbug.h>
#include <common/cachefsd.h>
#include <sys/fs/cachefs_fs.h>
#include <sys/fs/cachefs_dlog.h>
#include <sys/fs/cachefs_ioctl.h>
#include "cfsd_kmod.h"
#include "cfsd_maptbl.h"
#include "cfsd_logfile.h"
#include "cfsd_fscache.h"
#include "cfsd_cache.h"
#include "cfsd_all.h"
#include "cfsd_subr.h"

// declared in cfsd_main.cc
extern cfsd_all all;

//
//			cachefsd_caches_1_svc
//
// Description:
//	Returns list of caches on the system.
// Arguments:
//	inp	should be NULL
//	outp	should point to return object
//	reqp	svc_req info
// Returns:
//	Returns 1 for success 0 if an error occurs.
// Preconditions:
//	precond(reqp)

bool_t
cachefsd_caches_1_svc(void *inp, cachefsd_caches_return *outp,
    struct svc_req *reqp)
{
	dbug_enter("cachefsd_caches_1_svc");
	dbug_precond(reqp);

	dbug_assert(inp == NULL);
	dbug_assert(outp);

	if (inp || (outp == NULL))
		return (0);

	size_t cnt;
	int xx;
	size_t index;
	cfsd_cache *cachep;
	cachefsd_caches_id *headp, *idp;

	all.all_lock();
	headp = NULL;

	// if there are any caches
	cnt = all.all_cachelist_entries();
	if (cnt) {
		// allocate space for each cache information
		headp = idp = new cachefsd_caches_id[cnt];

		// for each cache
		for (index = 0; index < cnt; index++, idp++) {
			// get the cache
			cachep = all.all_cachelist_at(index);
			dbug_assert(cachep);

			// get the cache id and name
			idp->cci_cacheid = cachep->cache_cacheid();
			idp->cci_name = subr_strdup(cachep->cache_cachedir());
		}
	}

	// fill in the return object
	outp->ccr_modify = all.all_modify();
	outp->ccr_ids.ccr_ids_len = cnt;
	outp->ccr_ids.ccr_ids_val = headp;

	all.all_unlock();

	return (1);
}

//
//			cachefsd_cache_status_1_svc
//
// Description:
//	Returns status about a particular cache.
// Arguments:
//	inp	should be ptr to cache id
//	outp	should be ptr to place to put cache status
//	reqp	svc_req info
// Returns:
//	Returns 1 for success 0 if an error occurs.
// Preconditions:
//	precond(reqp)

bool_t
cachefsd_cache_status_1_svc(int *inp, cachefsd_cache_status *outp,
    struct svc_req *reqp)
{
	dbug_enter("cachefsd_cache_status_1_svc");
	dbug_precond(reqp);

	dbug_assert(inp);
	dbug_assert(outp);

	if ((inp == NULL) || (outp == NULL))
		return (0);

	memset(outp, 0, sizeof (*outp));

	size_t cnt, index;
	cfsd_cache *cachep;

	// find the requested cache
	all.all_lock();
	cnt = all.all_cachelist_entries();
	for (index = 0; index < cnt; index++) {
		// get the cache
		cachep = all.all_cachelist_at(index);
		dbug_assert(cachep);

		// if a match
		if (cachep->cache_cacheid() == *inp) {
			cachep->cache_lock();
			cachep->cache_refinc();
			cachep->cache_unlock();
			break;
		}
	}
	all.all_unlock();

	// if no match
	if (index >= cnt)
		return (1);

	// find a mounted file system in the cache
	cfsd_fscache *fscachep = NULL;
	cachep->cache_lock();
	cnt = cachep->cache_fscachelist_entries();
	for (index = 0; index < cnt; index++) {
		// get the fscache
		fscachep = cachep->cache_fscachelist_at(index);
		dbug_assert(fscachep);

		// mounted
		if (fscachep->fscache_mounted()) {
			fscachep->fscache_lock();
			fscachep->fscache_refinc();
			fscachep->fscache_unlock();
			break;
		}
		fscachep = NULL;
	}
	cachep->cache_unlock();

	outp->ccs_size = 0;
	outp->ccs_lrusize = 0;
	outp->ccs_packsize = 0;
	outp->ccs_freesize = 0;
	outp->ccs_lrutime = 0;

	cfsd_kmod kmod;
	while (fscachep) {
		cachefsio_getstats_t gs;
		int xx = kmod.kmod_setup(fscachep->fscache_mntpt());
		if (xx != 0) {
			dbug_print("err",
			    ("setup of kmod interface failed %d", xx));
			break;
		}
		xx = kmod.kmod_getstats(&gs);
		if (xx) {
			dbug_print("err", ("getstat failed %d", xx));
			break;
		}
		outp->ccs_size = gs.gs_total;
		outp->ccs_lrusize = gs.gs_gc + gs.gs_active;
		outp->ccs_packsize = gs.gs_packed;
		outp->ccs_freesize = gs.gs_free;
		outp->ccs_lrutime = gs.gs_gctime;

		fscachep->fscache_lock();
		fscachep->fscache_refdec();
		fscachep->fscache_unlock();
		break;
	}

	outp->ccs_id = cachep->cache_cacheid();
	outp->ccs_name = subr_strdup(cachep->cache_cachedir());
	outp->ccs_modify = cachep->cache_modify();
	cachep->cache_lock();
	cachep->cache_refdec();
	cachep->cache_unlock();

	return (1);
}

//
//			cachefsd_mounts_1_svc
//
// Description:
//	Returns the list of file systems that are in the cache.
// Arguments:
//	inp	should be ptr to cache id
//	outp	should be ptr to place to put mounts
//	reqp	svc_req info
// Returns:
//	Returns 1 for success 0 if an internal error occurs.
// Preconditions:
//	precond(reqp)

bool_t
cachefsd_mounts_1_svc(int *inp, cachefsd_mount_returns *outp,
    struct svc_req *reqp)
{
	dbug_enter("cachefsd_mounts_1_svc");
	dbug_precond(reqp);

	dbug_assert(inp);
	dbug_assert(outp);
	if ((inp == NULL) || (outp == NULL))
		return (0);

	memset(outp, 0, sizeof (*outp));

	size_t cnt, index;
	int xx;
	cfsd_cache *cachep;
	cfsd_fscache *fscachep;
	cachefsd_mount *headp, *idp;

	// find the requested cache
	all.all_lock();
	cnt = all.all_cachelist_entries();
	for (index = 0; index < cnt; index++) {
		// get the cache
		cachep = all.all_cachelist_at(index);
		dbug_assert(cachep);

		// if a match
		if (cachep->cache_cacheid() == *inp) {
			cachep->cache_lock();
			cachep->cache_refinc();
			cachep->cache_unlock();
			break;
		}
	}
	all.all_unlock();

	// if no match was found
	if (index >= cnt) {
		outp->cmr_error = ENOENT;
		return (1);
	}

	cachep->cache_lock();
	headp = NULL;

	// if there are any fscaches
	cnt = cachep->cache_fscachelist_entries();
	if (cnt) {
		// allocate space for each fscache information
		headp = idp = new cachefsd_mount[cnt];

		// for each fscache
		for (index = 0; index < cnt; index++, idp++) {
			// get the fscache
			fscachep = cachep->cache_fscachelist_at(index);
			dbug_assert(fscachep);

			// get the fscache id and name
			idp->cm_fsid = fscachep->fscache_fscacheid();
			idp->cm_name = subr_strdup(fscachep->fscache_name());
		}
	}

	// fill in the return object
	outp->cmr_modify = cachep->cache_modify();
	outp->cmr_error = 0;
	outp->cmr_names.cmr_names_len = cnt;
	outp->cmr_names.cmr_names_val = headp;

	cachep->cache_refdec();
	cachep->cache_unlock();

	return (1);
}

//
//			cachefsd_mount_stat_1_svc
//
// Description:
//	Returns status information about a single file system
//	in the cache.
// Arguments:
//	inp	should be which file system to get info for
//	outp	should be place to put mount info
//	reqp	svc_req info
// Returns:
//	Returns 1 for success 0 if an error occurs.
// Preconditions:
//	precond(reqp)

bool_t
cachefsd_mount_stat_1_svc(cachefsd_mount_stat_args *inp,
    cachefsd_mount_stat *outp, struct svc_req *reqp)
{
	dbug_enter("cachefsd_mount_stat_1_svc");
	dbug_precond(reqp);

	dbug_assert(inp);
	dbug_assert(outp);
	if ((inp == NULL) || (outp == NULL))
		return (0);

	memset(outp, 0, sizeof (*outp));

	size_t cnt, index;
	int xx;
	cfsd_cache *cachep;
	cfsd_fscache *fscachep;
	cachefsd_mount *headp, *idp;

	// find the requested cache
	all.all_lock();
	cnt = all.all_cachelist_entries();
	for (index = 0; index < cnt; index++) {
		// get the cache
		cachep = all.all_cachelist_at(index);
		dbug_assert(cachep);

		// if a match
		if (cachep->cache_cacheid() == inp->cma_cacheid) {
			cachep->cache_lock();
			cachep->cache_refinc();
			cachep->cache_unlock();
			break;
		}
	}
	all.all_unlock();

	// if no match was found
	if (index >= cnt) {
		return (1);
	}

	headp = NULL;

	// find the requested fscache
	cachep->cache_lock();
	cnt = cachep->cache_fscachelist_entries();
	for (index = 0; index < cnt; index++) {
		// get the fscache
		fscachep = cachep->cache_fscachelist_at(index);
		dbug_assert(fscachep);

		// if a match
		if (fscachep->fscache_fscacheid() == inp->cma_fsid) {
			fscachep->fscache_lock();
			fscachep->fscache_refinc();
			fscachep->fscache_unlock();
			break;
		}
	}
	cachep->cache_unlock();

	// if no match was found
	if (index >= cnt) {
		cachep->cache_lock();
		cachep->cache_refdec();
		cachep->cache_unlock();
		return (1);
	}

	fscachep->fscache_lock();

	// see if there are changes to roll to the server
	if ((fscachep->fscache_connected() == 0) &&
	    (fscachep->fscache_changes() == 0)) {
		char namebuf[MAXPATHLEN * 2];
		sprintf(namebuf, "%s/%s/%s", cachep->cache_cachedir(),
		    fscachep->fscache_name(), CACHEFS_DLOG_FILE);
		struct stat sinfo;
		if (stat(namebuf, &sinfo) == 0) {
			fscachep->fscache_changes(1);
		}
	}

	// fill in the return object
	outp->cms_cacheid = cachep->cache_cacheid();
	outp->cms_fsid = fscachep->fscache_fscacheid();
	outp->cms_name = subr_strdup(fscachep->fscache_name());
	outp->cms_backfs = subr_strdup(fscachep->fscache_backfs());
	outp->cms_mountpt = subr_strdup(fscachep->fscache_mntpt());
	outp->cms_backfstype = subr_strdup(fscachep->fscache_backfstype());
	outp->cms_writemode = NULL;
	outp->cms_options = subr_strdup(fscachep->fscache_cfsopt());
	outp->cms_mounted = fscachep->fscache_mounted();
	outp->cms_connected = fscachep->fscache_connected();
	outp->cms_reconcile = fscachep->fscache_reconcile();
	outp->cms_changes = fscachep->fscache_changes();
	outp->cms_time_state = fscachep->fscache_time_state();
	outp->cms_mnttime = fscachep->fscache_time_mnt();
	outp->cms_modify = fscachep->fscache_modify();

	fscachep->fscache_refdec();
	fscachep->fscache_unlock();

	cachep->cache_lock();
	cachep->cache_refdec();
	cachep->cache_unlock();

	return (1);
}

//
//			cachefsd_fs_mounted_1_svc
//
// Description:
//	Sent by the mount command to indicate a new file system
//	has been mounted
// Arguments:
//	inp	ptr to mount information
//	outp	should be null
//	reqp	svc_req info
// Returns:
//	Returns 1 for success 0 if an internal error occurs.
// Preconditions:
//	precond(inp)

bool_t
cachefsd_fs_mounted_1_svc(cachefsd_fs_mounted *inp, void *outp,
    struct svc_req *reqp)
{
	dbug_enter("cachefsd_fs_mounted_1_svc");
	dbug_precond(reqp);

	dbug_assert(inp);
	dbug_assert(outp == NULL);
	if ((inp == NULL) || outp)
		return (0);

	int error = 0;

	if (inp->mt_cachedir == NULL) {
		dbug_print("error", ("cachedir is null"));
		error = 1;
	}
	if (inp->mt_cacheid == NULL) {
		dbug_print("error", ("cacheid is null"));
		error = 1;
	}

	if (error == 0) {
		dbug_print("info", ("Mounted in %s file system %s",
		    inp->mt_cachedir, inp->mt_cacheid));
		subr_add_mount(&all, inp->mt_cachedir, inp->mt_cacheid);
	}

	return (1);
}

//
//			cachefsd_fs_unmounted_1_svc
//
// Description:
// Arguments:
//	inp
//	outp
//	reqp
// Returns:
//	Returns 1 for success 0 if an internal error occurs.
// Preconditions:
//	precond(inp)
//	precond(outp == NULL)
//	precond(reqp)

bool_t
cachefsd_fs_unmounted_1_svc(char **inp, int *outp, struct svc_req *reqp)
{
	dbug_enter("cachefsd_fs_unmounted_1_svc");

	dbug_precond(inp);
	dbug_precond(outp);
	dbug_precond(reqp);

	if ((inp == NULL) || (outp == NULL))
		return (0);

	memset(outp, 0, sizeof (*outp));

	if (*inp == NULL) {
		dbug_print("error", ("mntpt is null"));
		*outp = EIO;
		return (1);
	}

	size_t cnt1, cnt2, index1, index2;
	cfsd_cache *cachep;
	cfsd_fscache *fscachep = NULL;
	int found = 0;

	// for each cache
	all.all_lock();
	cnt1 = all.all_cachelist_entries();
	for (index1 = 0; index1 < cnt1; index1++) {
		// get the cache
		cachep = all.all_cachelist_at(index1);
		dbug_assert(cachep);

		// for each file system in this cache
		cachep->cache_lock();
		cnt2 = cachep->cache_fscachelist_entries();
		for (index2 = 0; index2 < cnt2; index2++) {
			// get the fscache
			fscachep = cachep->cache_fscachelist_at(index2);
			dbug_assert(fscachep);

			// skip if not mounted
			if (fscachep->fscache_mounted() == 0)
				continue;

			// if a match
			if (strcmp(fscachep->fscache_mntpt(), *inp)
			    == 0) {
				fscachep->fscache_lock();
				fscachep->fscache_refinc();
				fscachep->fscache_unlock();
				found = 1;
				break;
			}
		}
		cachep->cache_unlock();
		if (found)
			break;
		fscachep = NULL;
	}
	all.all_unlock();

	// if no match
	if (fscachep == NULL) {
		*outp = EIO;
	} else {
		*outp = fscachep->fscache_unmount();

		fscachep->fscache_lock();
		fscachep->fscache_refdec();
		fscachep->fscache_unlock();
	}
	return (1);
}

//
//			cachefsd_disconnection_1_svc
//
// Description:
// Arguments:
//	inp
//	outp
//	reqp
// Returns:
//	Returns 1 for success 0 if an internal error occurs.
// Preconditions:
//	precond(inp)
//	precond(outp)
//	precond(reqp)

bool_t
cachefsd_disconnection_1_svc(cachefsd_disconnection_args *inp, int *outp,
    struct svc_req *reqp)
{
	dbug_enter("cachefsd_disconnection_1_svc");

	dbug_precond(inp);
	dbug_precond(outp);
	dbug_precond(reqp);

	if ((inp == NULL) || (outp == NULL))
		return (0);

	memset(outp, 0, sizeof (*outp));

	size_t cnt1, cnt2, index1, index2;
	cfsd_cache *cachep;
	cfsd_fscache *fscachep = NULL;
	int found = 0;

	// for each cache
	all.all_lock();
	cnt1 = all.all_cachelist_entries();
	for (index1 = 0; index1 < cnt1; index1++) {
		// get the cache
		cachep = all.all_cachelist_at(index1);
		dbug_assert(cachep);

		// for each file system in this cache
		cachep->cache_lock();
		cnt2 = cachep->cache_fscachelist_entries();
		for (index2 = 0; index2 < cnt2; index2++) {
			// get the fscache
			fscachep = cachep->cache_fscachelist_at(index2);
			dbug_assert(fscachep);

			// if a match
			if (strcmp(fscachep->fscache_mntpt(), inp->cda_mntpt)
			    == 0) {
				fscachep->fscache_lock();
				fscachep->fscache_refinc();
				fscachep->fscache_unlock();
				found = 1;
				break;
			}
		}
		cachep->cache_unlock();
		if (found)
			break;
		fscachep = NULL;
	}
	all.all_unlock();

	/* if no match */
	if (fscachep == NULL) {
		*outp = 3;
	} else {
		*outp = fscachep->fscache_simdisconnect(inp->cda_disconnect);

		fscachep->fscache_lock();
		fscachep->fscache_refdec();
		fscachep->fscache_unlock();
	}
	return (1);
}

//
//			cachefsdprog_1_freeresult
//
// Description:
// Arguments:
//	transp
//	xdr_result
//	resultp
// Returns:
//	Returns ...
// Preconditions:
//	precond(transp)

int
cachefsdprog_1_freeresult(SVCXPRT *transp, xdrproc_t xdr_result,
    caddr_t resultp)
{
	dbug_enter("cachefsdprog_1_freeresult");

	dbug_precond(transp);

	(void) xdr_free(xdr_result, resultp);
	return (1);
}
