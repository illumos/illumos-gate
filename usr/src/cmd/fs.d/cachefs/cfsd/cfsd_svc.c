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
 * Copyright 1994-2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * RPC service routines.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <rpc/rpc.h>
#include <rpc/pmap_clnt.h> /* for pmap_unset */
#include <string.h> /* strcmp */
#include <signal.h>
#include <unistd.h> /* setsid */
#include <sys/types.h>
#include <sys/stat.h>
#include <time.h>
#include <memory.h>
#include <stropts.h>
#include <netconfig.h>
#include <sys/resource.h> /* rlimit */
#include <thread.h>
#include <synch.h>
#include <mdbug/mdbug.h>
#include <common/cachefsd.h>
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
#include "cfsd_subr.h"

/* declared in cfsd_main.c */
extern cfsd_all_object_t *all_object_p;

/*
 *			cachefsd_null_1_svc
 *
 * Description:
 *	Routine to process NULLPROC command, see /usr/include/rpc/clnt.h.
 * Arguments:
 *	inp	should be NULL
 *	outp	should be NULL
 *	reqp	svc_req info
 * Returns:
 *	Always returns 1, e.g. returns success result.
 * Preconditions:
 *	precond(reqp)
 */
bool_t
cachefsd_null_1_svc(void *inp, void *outp, struct svc_req *reqp)
{
	dbug_enter("cachefsd_null_1_svc");
	dbug_precond(reqp);

	dbug_assert(inp == NULL);
	dbug_assert(outp == NULL);

	dbug_leave("cachefsd_null_1_svc");
	return (1);
}

/*
 *			cachefsd_caches_1_svc
 *
 * Description:
 *	Returns list of caches on the system.
 * Arguments:
 *	inp	should be NULL
 *	outp	should point to return object
 *	reqp	svc_req info
 * Returns:
 *	Returns 1 for success 0 if an error occurs.
 * Preconditions:
 *	precond(reqp)
 */
bool_t
cachefsd_caches_1_svc(void *inp,
	cachefsd_caches_return *outp,
	struct svc_req *reqp)
{
	size_t cnt;
	size_t index;
	cfsd_cache_object_t *cache_object_p;
	cachefsd_caches_id *headp, *idp;

	dbug_enter("cachefsd_caches_1_svc");
	dbug_precond(reqp);

	dbug_assert(inp == NULL);
	dbug_assert(outp);

	if (inp || (outp == NULL)) {
		dbug_leave("cachefsd_caches_1_svc");
		return (0);
	}
	all_lock(all_object_p);
	headp = NULL;

	/* if there are any caches */
	cnt = all_object_p->i_cachecount;
	if (cnt) {
		/* allocate space for each cache information */
		headp = idp = cfsd_calloc(sizeof (cachefsd_caches_id) * cnt);

		/* for each cache */
		for (index = 0; index < cnt; index++, idp++) {
			/* get the cache */
			cache_object_p = all_cachelist_at(all_object_p, index);
			dbug_assert(cache_object_p);

			/* get the cache id and name */
			idp->cci_cacheid = cache_object_p->i_cacheid;
			idp->cci_name = subr_strdup(cache_object_p->i_cachedir);
		}
	}

	/* fill in the return object */
	outp->ccr_modify = all_object_p->i_modify;
	outp->ccr_ids.ccr_ids_len = cnt;
	outp->ccr_ids.ccr_ids_val = headp;

	all_unlock(all_object_p);

	dbug_leave("cachefsd_caches_1_svc");
	return (1);
}

/*
 *			cachefsd_cache_status_1_svc
 *
 * Description:
 *	Returns status about a particular cache.
 * Arguments:
 *	inp	should be ptr to cache id
 *	outp	should be ptr to place to put cache status
 *	reqp	svc_req info
 * Returns:
 *	Returns 1 for success 0 if an error occurs.
 * Preconditions:
 *	precond(reqp)
 */
bool_t
cachefsd_cache_status_1_svc(int *inp, struct cachefsd_cache_status *outp,
    struct svc_req *reqp)
{
	cfsd_fscache_object_t *fscache_object_p = NULL;
	size_t cnt, index;
	cfsd_cache_object_t *cache_object_p;
	cfsd_kmod_object_t *kmod_object_p;
	cachefsio_getstats_t gs;
	int xx;

	dbug_enter("cachefsd_cache_status_1_svc");
	dbug_precond(reqp);

	dbug_assert(inp);
	dbug_assert(outp);

	if ((inp == NULL) || (outp == NULL)) {
		dbug_leave("cachefsd_cache_status_1_svc");
		return (0);
	}
	memset(outp, 0, sizeof (*outp));

	/* find the requested cache */
	all_lock(all_object_p);
	cnt = all_object_p->i_cachecount;
	for (index = 0; index < cnt; index++) {
		/* get the cache */
		cache_object_p = all_cachelist_at(all_object_p, index);
		dbug_assert(cache_object_p);

		/* if a match */
		if (cache_object_p->i_cacheid == *inp) {
			cache_lock(cache_object_p);
			cache_object_p->i_refcnt++;
			cache_unlock(cache_object_p);
			break;
		}
	}
	all_unlock(all_object_p);

	/* if no match */
	if (index >= cnt) {
		dbug_leave("cachefsd_cache_status_1_svc");
		return (1);
	}
	/* find a mounted file system in the cache */
	cache_lock(cache_object_p);
	cnt = cache_object_p->i_fscachecount;
	for (index = 0; index < cnt; index++) {
		/* get the fscache */
		fscache_object_p = cache_fscachelist_at(cache_object_p, index);
		dbug_assert(fscache_object_p);

		/* mounted */
		if (fscache_object_p->i_mounted) {
			fscache_lock(fscache_object_p);
			fscache_object_p->i_refcnt++;
			fscache_unlock(fscache_object_p);
			break;
		}
		fscache_object_p = NULL;
	}
	cache_unlock(cache_object_p);

	outp->ccs_size = 0;
	outp->ccs_lrusize = 0;
	outp->ccs_packsize = 0;
	outp->ccs_freesize = 0;
	outp->ccs_lrutime = 0;

	kmod_object_p = cfsd_kmod_create();
	if (fscache_object_p) {
		xx = kmod_setup(kmod_object_p, fscache_object_p->i_mntpt);
		if (xx != 0) {
			dbug_print(("err",
			    "setup of kmod interface failed %d", xx));
		} else if ((xx = kmod_getstats(kmod_object_p, &gs)) != 0) {
			dbug_print(("err", "getstat failed %d", xx));
		} else {
			outp->ccs_size = gs.gs_total;
			outp->ccs_lrusize = gs.gs_gc + gs.gs_active;
			outp->ccs_packsize = gs.gs_packed;
			outp->ccs_freesize = gs.gs_free;
			outp->ccs_lrutime = gs.gs_gctime;

			fscache_lock(fscache_object_p);
			fscache_object_p->i_refcnt--;
			fscache_unlock(fscache_object_p);
		}
	}
	cfsd_kmod_destroy(kmod_object_p);

	outp->ccs_id = cache_object_p->i_cacheid;
	outp->ccs_name = subr_strdup(cache_object_p->i_cachedir);
	outp->ccs_modify = cache_object_p->i_modify;
	cache_lock(cache_object_p);
	cache_object_p->i_refcnt--;
	cache_unlock(cache_object_p);

	dbug_leave("cachefsd_cache_status_1_svc");
	return (1);
}

/*
 *			cachefsd_mounts_1_svc
 *
 * Description:
 *	Returns the list of file systems that are in the cache.
 * Arguments:
 *	inp	should be ptr to cache id
 *	outp	should be ptr to place to put mounts
 *	reqp	svc_req info
 * Returns:
 *	Returns 1 for success 0 if an internal error occurs.
 * Preconditions:
 *	precond(reqp)
 */
bool_t
cachefsd_mounts_1_svc(int *inp, struct cachefsd_mount_returns *outp,
    struct svc_req *reqp)
{
	size_t cnt, index;
	cfsd_cache_object_t *cache_object_p;
	cfsd_fscache_object_t *fscache_object_p;
	struct cachefsd_mount *headp, *idp;

	dbug_enter("cachefsd_mounts_1_svc");
	dbug_precond(reqp);

	dbug_assert(inp);
	dbug_assert(outp);
	if ((inp == NULL) || (outp == NULL)) {
		dbug_leave("cachefsd_mounts_1_svc");
		return (0);
	}
	memset(outp, 0, sizeof (*outp));

	/* find the requested cache */
	all_lock(all_object_p);
	cnt = all_object_p->i_cachecount;
	for (index = 0; index < cnt; index++) {
		/* get the cache */
		cache_object_p = all_cachelist_at(all_object_p, index);
		dbug_assert(cache_object_p);

		/* if a match */
		if (cache_object_p->i_cacheid == *inp) {
			cache_lock(cache_object_p);
			cache_object_p->i_refcnt++;
			cache_unlock(cache_object_p);
			break;
		}
	}
	all_unlock(all_object_p);

	/* if no match was found */
	if (index >= cnt) {
		outp->cmr_error = ENOENT;
		dbug_leave("cachefsd_mounts_1_svc");
		return (1);
	}

	cache_lock(cache_object_p);
	headp = NULL;

	/* if there are any fscaches */
	cnt = cache_object_p->i_fscachecount;
	if (cnt) {
		/* allocate space for each fscache information */
		headp = idp = cfsd_calloc(sizeof (cachefsd_mount) * cnt);
		/* for each fscache */
		for (index = 0; index < cnt; index++, idp++) {
			/* get the fscache */
			fscache_object_p =
			    cache_fscachelist_at(cache_object_p, index);
			dbug_assert(fscache_object_p);

			/* get the fscache id and name */
			idp->cm_fsid = fscache_object_p->i_fscacheid;
			idp->cm_name = subr_strdup(fscache_object_p->i_name);
		}
	}

	/* fill in the return object */
	outp->cmr_modify = cache_object_p->i_modify;
	outp->cmr_error = 0;
	outp->cmr_names.cmr_names_len = cnt;
	outp->cmr_names.cmr_names_val = headp;

	cache_object_p->i_refcnt--;
	cache_unlock(cache_object_p);

	dbug_leave("cachefsd_mounts_1_svc");
	return (1);
}

/*
 *			cachefsd_mount_stat_1_svc
 *
 * Description:
 *	Returns status information about a single file system
 *	in the cache.
 * Arguments:
 *	inp	should be which file system to get info for
 *	outp	should be place to put mount info
 *	reqp	svc_req info
 * Returns:
 *	Returns 1 for success 0 if an error occurs.
 * Preconditions:
 *	precond(reqp)
 */
bool_t
cachefsd_mount_stat_1_svc(struct cachefsd_mount_stat_args *inp,
    struct cachefsd_mount_stat *outp, struct svc_req *reqp)
{
	size_t cnt, index;
	cfsd_cache_object_t *cache_object_p;
	cfsd_fscache_object_t *fscache_object_p;
	char namebuf[MAXPATHLEN];
	struct stat sinfo;

	dbug_enter("cachefsd_mount_stat_1_svc");
	dbug_precond(reqp);

	dbug_assert(inp);
	dbug_assert(outp);
	if ((inp == NULL) || (outp == NULL)) {
		dbug_leave("cachefsd_mount_stat_1_svc");
		return (0);
	}
	memset(outp, 0, sizeof (*outp));

	/* find the requested cache */
	all_lock(all_object_p);
	cnt = all_object_p->i_cachecount;
	for (index = 0; index < cnt; index++) {
		/* get the cache */
		cache_object_p = all_cachelist_at(all_object_p, index);
		dbug_assert(cache_object_p);

		/* if a match */
		if (cache_object_p->i_cacheid == inp->cma_cacheid) {
			cache_lock(cache_object_p);
			cache_object_p->i_refcnt++;
			cache_unlock(cache_object_p);
			break;
		}
	}
	all_unlock(all_object_p);

	/* if no match was found */
	if (index >= cnt) {
		dbug_leave("cachefsd_mount_stat_1_svc");
		return (1);
	}

	/* find the requested fscache */
	cache_lock(cache_object_p);
	cnt = cache_object_p->i_fscachecount;
	for (index = 0; index < cnt; index++) {
		/* get the fscache */
		fscache_object_p = cache_fscachelist_at(cache_object_p, index);
		dbug_assert(fscache_object_p);

		/* if a match */
		if (fscache_object_p->i_fscacheid == inp->cma_fsid) {
			fscache_lock(fscache_object_p);
			fscache_object_p->i_refcnt++;
			fscache_unlock(fscache_object_p);
			break;
		}
	}
	cache_unlock(cache_object_p);

	/* if no match was found */
	if (index >= cnt) {
		cache_lock(cache_object_p);
		cache_object_p->i_refcnt--;
		cache_unlock(cache_object_p);
		dbug_leave("cachefsd_mount_stat_1_svc");
		return (1);
	}

	fscache_lock(fscache_object_p);

	/* see if there are changes to roll to the server */
	if ((fscache_object_p->i_connected == 0) &&
	    (fscache_object_p->i_changes == 0)) {
		snprintf(namebuf, sizeof (namebuf), "%s/%s/%s",
		    cache_object_p->i_cachedir, fscache_object_p->i_name,
		    CACHEFS_DLOG_FILE);
		if (stat(namebuf, &sinfo) == 0) {
			fscache_changes(fscache_object_p, 1);
		}
	}

	/* fill in the return object */
	outp->cms_cacheid = cache_object_p->i_cacheid;
	outp->cms_fsid = fscache_object_p->i_fscacheid;
	outp->cms_name = subr_strdup(fscache_object_p->i_name);
	outp->cms_backfs = subr_strdup(fscache_object_p->i_backfs);
	outp->cms_mountpt = subr_strdup(fscache_object_p->i_mntpt);
	outp->cms_backfstype = subr_strdup(fscache_object_p->i_backfstype);
	outp->cms_writemode = NULL;
	outp->cms_options = subr_strdup(fscache_object_p->i_cfsopt);
	outp->cms_mounted = fscache_object_p->i_mounted;
	outp->cms_connected = fscache_object_p->i_connected;
	outp->cms_reconcile = fscache_object_p->i_reconcile;
	outp->cms_changes = fscache_object_p->i_changes;
	outp->cms_time_state = fscache_object_p->i_time_state;
	outp->cms_mnttime = fscache_object_p->i_time_mnt;
	outp->cms_modify = fscache_object_p->i_modify;

	fscache_object_p->i_refcnt--;
	fscache_unlock(fscache_object_p);

	cache_lock(cache_object_p);
	cache_object_p->i_refcnt--;
	cache_unlock(cache_object_p);

	dbug_leave("cachefsd_mount_stat_1_svc");
	return (1);
}

/*
 *			cachefsd_fs_mounted_1_svc
 *
 * Description:
 *	Sent by the mount command to indicate a new file system
 *	has been mounted
 * Arguments:
 *	inp	ptr to mount information
 *	outp	should be null
 *	reqp	svc_req info
 * Returns:
 *	Returns 1 for success 0 if an internal error occurs.
 * Preconditions:
 *	precond(inp)
 */
bool_t
cachefsd_fs_mounted_1_svc(struct cachefsd_fs_mounted *inp, void *outp,
    struct svc_req *reqp)
{
	int error = 0;

	dbug_enter("cachefsd_fs_mounted_1_svc");
	dbug_precond(reqp);

	dbug_assert(inp);
	dbug_assert(outp == NULL);
	if ((inp == NULL) || outp) {
		dbug_leave("cachefsd_fs_mounted_1_svc");
		return (0);
	}

	if (inp->mt_cachedir == NULL) {
		dbug_print(("error", "cachedir is null"));
		error = 1;
	}
	if (inp->mt_cacheid == NULL) {
		dbug_print(("error", "cacheid is null"));
		error = 1;
	}

	if (error == 0) {
		dbug_print(("info", "Mounted in %s file system %s",
		    inp->mt_cachedir, inp->mt_cacheid));
		subr_add_mount(all_object_p, inp->mt_cachedir, inp->mt_cacheid);
	}

	dbug_leave("cachefsd_fs_mounted_1_svc");
	return (1);
}

/*
 *			cachefsd_fs_unmounted_1_svc
 *
 * Description:
 * Arguments:
 *	inp
 *	outp
 *	reqp
 * Returns:
 *	Returns 1 for success 0 if an internal error occurs.
 * Preconditions:
 *	precond(inp)
 *	precond(outp == NULL)
 *	precond(reqp)
 */
bool_t
cachefsd_fs_unmounted_1_svc(struct cachefsd_fs_unmounted *inp, int *outp,
    struct svc_req *reqp)
{
	size_t cnt1, cnt2, index1, index2;
	cfsd_cache_object_t *cache_object_p;
	cfsd_fscache_object_t *fscache_object_p = NULL;
	int found = 0;
	int flag = 0;

	dbug_enter("cachefsd_fs_unmounted_1_svc");

	dbug_precond(inp);
	dbug_precond(outp);
	dbug_precond(reqp);

	if ((inp == NULL) || (outp == NULL)) {
		dbug_leave("cachefsd_fs_unmounted_1_svc");
		return (0);
	}
	memset(outp, 0, sizeof (*outp));

	if (inp->mntpt == NULL) {
		dbug_print(("error", "mntpt is null"));
		*outp = EIO;
		dbug_leave("cachefsd_fs_unmounted_1_svc");
		return (1);
	}

	/* for each cache */
	all_lock(all_object_p);
	cnt1 = all_object_p->i_cachecount;
	for (index1 = 0; index1 < cnt1; index1++) {
		/* get the cache */
		cache_object_p = all_cachelist_at(all_object_p, index1);
		dbug_assert(cache_object_p);

		/* for each file system in this cache */
		cache_lock(cache_object_p);
		cnt2 = cache_object_p->i_fscachecount;
		for (index2 = 0; index2 < cnt2; index2++) {
			/* get the fscache */
			fscache_object_p =
			    cache_fscachelist_at(cache_object_p, index2);
			dbug_assert(fscache_object_p);

			/* skip if not mounted */
			if (fscache_object_p->i_mounted == 0)
				continue;

			/* if a match */
			if (strcmp(fscache_object_p->i_mntpt,
				inp->mntpt) == 0) {
				fscache_lock(fscache_object_p);
				fscache_object_p->i_refcnt++;
				flag = inp->flag;
				fscache_unlock(fscache_object_p);
				found = 1;
				break;
			}
		}
		cache_unlock(cache_object_p);
		if (found)
			break;
		fscache_object_p = NULL;
	}
	all_unlock(all_object_p);

	/* if no match */
	if (fscache_object_p == NULL) {
		*outp = EIO;
	} else {
		*outp = fscache_unmount(fscache_object_p, flag);

		fscache_lock(fscache_object_p);
		fscache_object_p->i_refcnt--;
		fscache_unlock(fscache_object_p);
	}
	dbug_leave("cachefsd_fs_unmounted_1_svc");
	return (1);
}

/*
 *			cachefsd_disconnection_1_svc
 *
 * Description:
 * Arguments:
 *	inp
 *	outp
 *	reqp
 * Returns:
 *	Returns 1 for success 0 if an internal error occurs.
 * Preconditions:
 *	precond(inp)
 *	precond(outp)
 *	precond(reqp)
 */
bool_t
cachefsd_disconnection_1_svc(struct cachefsd_disconnection_args *inp, int *outp,
    struct svc_req *reqp)
{
	size_t cnt1, cnt2, index1, index2;
	cfsd_cache_object_t *cache_object_p;
	cfsd_fscache_object_t *fscache_object_p = NULL;
	int found = 0;

	dbug_enter("cachefsd_disconnection_1_svc");

	dbug_precond(inp);
	dbug_precond(outp);
	dbug_precond(reqp);

	if ((inp == NULL) || (outp == NULL)) {
		dbug_leave("cachefsd_disconnection_1_svc");
		return (0);
	}
	memset(outp, 0, sizeof (*outp));

	/* for each cache */
	all_lock(all_object_p);
	cnt1 = all_object_p->i_cachecount;
	for (index1 = 0; index1 < cnt1; index1++) {
		/* get the cache */
		cache_object_p = all_cachelist_at(all_object_p, index1);
		dbug_assert(cache_object_p);

		/* for each file system in this cache */
		cache_lock(cache_object_p);
		cnt2 = cache_object_p->i_fscachecount;
		for (index2 = 0; index2 < cnt2; index2++) {
			/* get the fscache */
			fscache_object_p =
			    cache_fscachelist_at(cache_object_p, index2);
			dbug_assert(fscache_object_p);

			/* if a match */
			if (strcmp(fscache_object_p->i_mntpt, inp->cda_mntpt)
			    == 0) {
				fscache_lock(fscache_object_p);
				fscache_object_p->i_refcnt++;
				fscache_unlock(fscache_object_p);
				found = 1;
				break;
			}
		}
		cache_unlock(cache_object_p);
		if (found)
			break;
		fscache_object_p = NULL;
	}
	all_unlock(all_object_p);

	/* if no match */
	if (fscache_object_p == NULL) {
		*outp = 3;
	} else {
		*outp = fscache_simdisconnect(fscache_object_p,
		    inp->cda_disconnect);

		fscache_lock(fscache_object_p);
		fscache_object_p->i_refcnt--;
		fscache_unlock(fscache_object_p);
	}
	dbug_leave("cachefsd_disconnection_1_svc");
	return (1);
}

/*
 *			cachefsdprog_1_freeresult
 *
 * Description:
 * Arguments:
 *	transp
 *	xdr_result
 *	resultp
 * Returns:
 *	Returns ...
 * Preconditions:
 *	precond(transp)
 */
int
cachefsdprog_1_freeresult(SVCXPRT *transp, xdrproc_t xdr_result,
	caddr_t resultp)
{
	dbug_enter("cachefsdprog_1_freeresult");

	dbug_precond(transp);

	(void) xdr_free(xdr_result, resultp);
	dbug_leave("cachefsdprog_1_freeresult");
	return (1);
}
