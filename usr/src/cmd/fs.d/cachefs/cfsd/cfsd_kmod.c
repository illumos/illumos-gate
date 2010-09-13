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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Source file for the cfsd_kmod class.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/fcntl.h>
#include <sys/cred.h>
#include <sys/vnode.h>
#include <sys/vfs.h>
#include <sys/fs/cachefs_fs.h>
#include <sys/fs/cachefs_dlog.h>
#include <sys/fs/cachefs_ioctl.h>
#include <mdbug/mdbug.h>
#include "cfsd.h"
#include "cfsd_kmod.h"

/*
 * copy_cred (copy dl_cred_t followed by a list of gid_t)
 */

static void
copy_cred(dl_cred_t *dst, const dl_cred_t *src)
{
	int n = src->cr_ngroups;

	if (n > NGROUPS_MAX_DEFAULT)
		n = NGROUPS_MAX_DEFAULT;

	(void) memcpy(dst, src, sizeof (*dst) + (n - 1) * sizeof (gid_t));
	dst->cr_ngroups = n;
}

/*
 * ------------------------------------------------------------
 *			cfsd_kmod_create
 *
 * Description:
 * Arguments:
 * Returns:
 * Preconditions:
 */

cfsd_kmod_object_t *
cfsd_kmod_create(void)
{
	cfsd_kmod_object_t *kmod_object_p;

	dbug_enter("cfsd_kmod_create");
	kmod_object_p = cfsd_calloc(sizeof (cfsd_kmod_object_t));

	kmod_object_p->i_fd = -1;

	dbug_leave("cfsd_kmod_create");
	return (kmod_object_p);
}

/*
 * ------------------------------------------------------------
 *			cfsd_kmod_destory
 *
 * Description:
 * Arguments:
 * Returns:
 * Preconditions:
 */


void
cfsd_kmod_destroy(cfsd_kmod_object_t *kmod_object_p)
{
	dbug_enter("cfsd_kmod_destroy");
	dbug_precond(kmod_object_p);

	/* clean up old stuff */
	kmod_shutdown(kmod_object_p);

	cfsd_free(kmod_object_p);
	dbug_leave("cfsd_kmod_destroy");
}

/*
 * ------------------------------------------------------------
 *			kmod_setup
 *
 * Description:
 * Arguments:
 *	path
 * Returns:
 *	Returns ...
 * Preconditions:
 *	precond(path)
 */
int
kmod_setup(cfsd_kmod_object_t *kmod_object_p, const char *path)
{
	int xx;
	int error;

	dbug_enter("kmod_setup");
	dbug_precond(kmod_object_p);
	dbug_precond(path);

	/* clean up old stuff */
	kmod_shutdown(kmod_object_p);

	/* try to open the file */
	dbug_assert(kmod_object_p->i_fd == -1);
	kmod_object_p->i_fd = open(path, O_RDONLY);

	/* return result */
	if (kmod_object_p->i_fd == -1) {
		xx = errno;
		dbug_print(("err", "open of %s failed %d", path, xx));
	} else {
		xx = 0;
		strlcpy(kmod_object_p->i_path, path,
		    sizeof (kmod_object_p->i_path));
		dbug_print(("info", "opened %s on fd %d", path,
		    kmod_object_p->i_fd));

		/* tell the cachefs kmod we are here */
		xx = kmod_doioctl(kmod_object_p, CFSDCMD_DAEMONID,
		    NULL, 0, NULL, 0);
		if (xx) {
			error = errno;
			dbug_print(("ioctl", "daemonid error %d", error));
		}
	}

	dbug_leave("kmod_setup");
	return (xx);
}

/*
 *			kmod_shutdown
 *
 * Description:
 * Arguments:
 * Returns:
 * Preconditions:
 */
void
kmod_shutdown(cfsd_kmod_object_t *kmod_object_p)
{
	dbug_enter("kmod_shutdown");
	dbug_precond(kmod_object_p);

	/* close down the old fd if necessary */
	if (kmod_object_p->i_fd >= 0) {
		if (close(kmod_object_p->i_fd))
			dbug_print(("err", "cannot close kmod fd, %d", errno));
	}
	kmod_object_p->i_fd = -1;
	dbug_leave("kmod_shutdown");
}

/*
 * ------------------------------------------------------------
 *			kmod_xwait
 *
 * Description:
 * Arguments:
 * Returns:
 *	Returns ...
 * Preconditions:
 */
int
kmod_xwait(cfsd_kmod_object_t *kmod_object_p)
{
	int xx;
	int error = 0;

	dbug_enter("kmod_xwait");
	dbug_precond(kmod_object_p);

	xx = kmod_doioctl(kmod_object_p, CFSDCMD_XWAIT, NULL, 0, NULL, 0);
	if (xx)
		error = errno;
	dbug_print(("ioctl", "returns %d, error %d", xx, error));
	dbug_leave("kmod_xwait");
	return (error);
}

/*
 * ------------------------------------------------------------
 *			kmod_stateget
 *
 * Description:
 * Arguments:
 * Returns:
 *	Returns ...
 * Preconditions:
 */
int
kmod_stateget(cfsd_kmod_object_t *kmod_object_p)
{
	int state;
	int xx;

	dbug_enter("kmod_stateget");
	dbug_precond(kmod_object_p);

	xx = kmod_doioctl(kmod_object_p, CFSDCMD_STATEGET, NULL, 0, &state,
	    sizeof (state));
	dbug_print(("ioctl", "returns %d, state %d", xx, state));
	if (xx == -1) {
		/* XXX do what? */
		dbug_assert(0);
	}
	dbug_leave("kmod_stateget");
	return (state);
}

/*
 * ------------------------------------------------------------
 *			kmod_stateset
 *
 * Description:
 * Arguments:
 *	state
 * Returns:
 *	Returns ...
 * Preconditions:
 */
int
kmod_stateset(cfsd_kmod_object_t *kmod_object_p, int state)
{
	int xx;
	int error = 0;

	dbug_enter("kmod_stateset");
	dbug_precond(kmod_object_p);

	xx = kmod_doioctl(kmod_object_p, CFSDCMD_STATESET, &state,
	    sizeof (state), NULL, 0);
	if (xx)
		error = errno;
	dbug_print(("ioctl", "returns %d, state set to %d", xx, state));
	dbug_leave("kmod_stateset");
	return (error);
}

/*
 * ------------------------------------------------------------
 *			kmod_exists
 *
 * Description:
 * Arguments:
 *	cidp
 * Returns:
 *	Returns ...
 * Preconditions:
 *	precond(cidp)
 */
int
kmod_exists(cfsd_kmod_object_t *kmod_object_p, cfs_cid_t *cidp)
{
	int xx;
	int error = 0;

	dbug_enter("kmod_exists");
	dbug_precond(kmod_object_p);
	dbug_precond(cidp);

	xx = kmod_doioctl(kmod_object_p, CFSDCMD_EXISTS, cidp,
	    sizeof (cfs_cid_t), NULL, 0);
	if (xx)
		error = errno;
	dbug_print(("ioctl", "returns %d, error %d", xx, error));
	dbug_print(("ioctl", "   cid %08x", cidp->cid_fileno));
	dbug_leave("kmod_exists");
	return (error);
}

/*
 * ------------------------------------------------------------
 *			kmod_lostfound
 *
 * Description:
 * Arguments:
 *	cidp
 * Returns:
 *	Returns ...
 * Preconditions:
 *	precond(cidp)
 */
int
kmod_lostfound(cfsd_kmod_object_t *kmod_object_p, cfs_cid_t *cidp,
	const char *namep, char *newnamep)
{
	cachefsio_lostfound_arg_t info;
	cachefsio_lostfound_return_t ret;
	int error = 0;
	int xx;

	dbug_enter("kmod_lostfound");
	dbug_precond(kmod_object_p);
	dbug_precond(cidp);
	dbug_precond(namep);
	dbug_precond(newnamep);
	dbug_precond(strlen(namep) < (size_t)MAXNAMELEN);

	info.lf_cid = *cidp;
	strlcpy(info.lf_name, namep, sizeof (info.lf_name));

	xx = kmod_doioctl(kmod_object_p, CFSDCMD_LOSTFOUND, &info,
	    sizeof (info), &ret, sizeof (ret));
	if (xx)
		error = errno;
	dbug_print(("ioctl", "returns %d, error %d", xx, error));
	dbug_print(("ioctl", "   cid %08x", cidp->cid_fileno));
	dbug_print(("ioctl", "   suggested name '%s'", namep));
	if (xx == 0) {
		dbug_print(("ioctl", "   new name '%s'", ret.lf_name));
		dbug_assert(strlen(ret.lf_name) < (size_t)MAXNAMELEN);
		if (newnamep)
			strlcpy(newnamep, ret.lf_name, MAXNAMELEN);
	}
	dbug_leave("kmod_lostfound");
	return (error);
}

#if 0
/*
 * ------------------------------------------------------------
 *			kmod_lostfoundall
 *
 * Description:
 * Arguments:
 * Returns:
 *	Returns ...
 * Preconditions:
 */
int
kmod_lostfoundall(cfsd_kmod_object_t *kmod_object_p)
{
	int error = 0;
	int xx = -1;

	dbug_enter("kmod_lostfoundall");
	dbug_precond(kmod_object_p);

	/* xx = ioctl(kmod_object_p->i_fd, CACHEFSIO_LOSTFOUNDALL, 0); */
	if (xx)
		error = errno;
	dbug_print(("ioctl", "returns %d, error %d", xx, error));
	dbug_leave("kmod_lostfoundall");
	return (error);
}
/*
 *			kmod_rofs
 *
 * Description:
 * Arguments:
 * Returns:
 *	Returns ...
 * Preconditions:
 */
int
kmod_rofs(cfsd_kmod_object_t *kmod_object_p)
{
	int error = 0;
	int xx = -1;

	dbug_enter("kmod_rofs");
	dbug_precond(kmod_object_p);

	/* xx = ioctl(kmod_object_p->i_fd, CACHEFSIO_ROFS, 0); */
	if (xx)
		error = errno;
	dbug_print(("ioctl", "returns %d, error %d", xx, error));
	dbug_leave("kmod_rofs");
	return (error);
}
#endif

/*
 *			kmod_rootfid
 *
 * Description:
 *	Fills in fidp with the fid of the root of the file system.
 * Arguments:
 *	fidp
 * Returns:
 *	Returns 0 for success, errno value for an error
 * Preconditions:
 *	precond(fidp)
 */
int
kmod_rootfid(cfsd_kmod_object_t *kmod_object_p, cfs_fid_t *fidp)
{
	int error = 0;
	int xx;

	dbug_enter("kmod_rootfid");
	dbug_precond(kmod_object_p);
	dbug_precond(fidp);

	xx = kmod_doioctl(kmod_object_p, CFSDCMD_ROOTFID, NULL, 0, fidp,
	    sizeof (*fidp));
	if (xx)
		error = errno;
	dbug_print(("ioctl", "returns %d, error %d", xx, error));
	dbug_leave("kmod_rootfid");
	return (error);
}


/*
 *			kmod_getstats
 *
 * Description:
 * Arguments:
 *	gsp
 * Returns:
 *	Returns ...
 * Preconditions:
 *	precond(gsp)
 */
int
kmod_getstats(cfsd_kmod_object_t *kmod_object_p, cachefsio_getstats_t *gsp)
{
	int error = 0;
	int xx;

	dbug_enter("kmod_getstats");
	dbug_precond(kmod_object_p);

	dbug_precond(gsp);

	xx = kmod_doioctl(kmod_object_p, CFSDCMD_GETSTATS, NULL, 0, gsp,
	    sizeof (*gsp));
	if (xx)
		error = errno;
	dbug_print(("ioctl", "returns %d, error %d", xx, error));
	dbug_print(("ioctl", "total blocks %d", gsp->gs_total));
	dbug_print(("ioctl", "gc blocks %d", gsp->gs_gc));
	dbug_print(("ioctl", "active blocks %d", gsp->gs_active));
	dbug_print(("ioctl", "packed blocks %d", gsp->gs_packed));
	dbug_print(("ioctl", "free blocks %d", gsp->gs_free));
	dbug_print(("ioctl", "gctime %x", gsp->gs_gctime));
	dbug_leave("kmod_getstats");
	return (error);
}

/*
 * ------------------------------------------------------------
 *			kmod_getinfo
 *
 * Description:
 * Arguments:
 *	filep
 * Returns:
 *	Returns ...
 * Preconditions:
 *	precond(filep)
 *	precond(infop)
 */
int
kmod_getinfo(cfsd_kmod_object_t *kmod_object_p, cfs_cid_t *filep,
	cachefsio_getinfo_t *infop)
{
	int error = 0;
	int xx;

	dbug_enter("kmod_getinfo");
	dbug_precond(kmod_object_p);

	dbug_precond(filep);
	dbug_precond(infop);

	xx = kmod_doioctl(kmod_object_p, CFSDCMD_GETINFO, filep,
	    sizeof (*filep), infop, sizeof (*infop));
	if (xx)
		error = errno;

	dbug_print(("ioctl", "returns %d, error %d", xx, error));
	dbug_print(("ioctl", "   file cid %08x", filep->cid_fileno));
	if (xx == 0) {
		dbug_print(("ioctl", "   modified %d  seq %d",
		    infop->gi_modified, infop->gi_seq));
		dbug_print(("ioctl", "   name \"%s\"", infop->gi_name));
		dbug_print(("ioctl", "   parent cid %08x",
		    infop->gi_pcid.cid_fileno));
		infop->gi_attr.va_mask = AT_ALL;
		kmod_print_attr(&infop->gi_attr);
	}
	dbug_leave("kmod_getinfo");
	return (error);
}

/*
 * ------------------------------------------------------------
 *			kmod_cidtofid
 *
 * Description:
 * Arguments:
 *	cidp
 *	fidp
 * Returns:
 *	Returns ...
 * Preconditions:
 *	precond(cidp)
 *	precond(fidp)
 */
int
kmod_cidtofid(cfsd_kmod_object_t *kmod_object_p, cfs_cid_t *cidp,
		cfs_fid_t *fidp)
{
	int error = 0;
	int xx;

	dbug_enter("kmod_cidtofid");
	dbug_precond(kmod_object_p);

	dbug_precond(cidp);
	dbug_precond(fidp);

	xx = kmod_doioctl(kmod_object_p, CFSDCMD_CIDTOFID, cidp, sizeof (*cidp),
	    fidp, sizeof (*fidp));
	if (xx)
		error = errno;

	dbug_print(("ioctl", "returns %d, error %d", xx, error));
	dbug_print(("ioctl", "   cid %08x", cidp->cid_fileno));
	if (xx == 0) {
		kmod_format_fid(kmod_object_p, fidp);
		dbug_print(("ioctl", "   fid \"%s\"", kmod_object_p->i_fidbuf));
	}
	dbug_leave("kmod_cidtofid");
	return (error);
}

/*
 * ------------------------------------------------------------
 *			kmod_getattrfid
 *
 * Description:
 * Arguments:
 *	fidp
 *	credp
 *	vattrp
 * Returns:
 *	Returns ...
 * Preconditions:
 *	precond(fidp)
 *	precond(credp)
 *	precond(vattrp)
 */
int
kmod_getattrfid(cfsd_kmod_object_t *kmod_object_p, cfs_fid_t *fidp,
	dl_cred_t *credp, vattr_t *vattrp)
{
	int error = 0;
	int xx;
	cachefsio_getattrfid_t info;

	dbug_enter("kmod_getattrfid");
	dbug_precond(kmod_object_p);

	dbug_precond(fidp);
	dbug_precond(credp);
	dbug_precond(vattrp);

	info.cg_backfid = *fidp;

	copy_cred(&info.cg_cred, credp);

	xx = kmod_doioctl(kmod_object_p, CFSDCMD_GETATTRFID, &info,
	    sizeof (info), vattrp, sizeof (*vattrp));
	if (xx)
		error = errno;

	dbug_print(("ioctl", "returns %d, error %d", xx, error));
	kmod_format_fid(kmod_object_p, fidp);
	dbug_print(("ioctl", "   fid \"%s\"", kmod_object_p->i_fidbuf));
	kmod_print_cred(credp);
	if (xx == 0) {
		vattrp->va_mask = AT_ALL;
		kmod_print_attr(vattrp);
	}
	dbug_leave("kmod_getattrfid");
	return (error);
}

/*
 * ------------------------------------------------------------
 *			kmod_getattrname
 *
 * Description:
 * Arguments:
 *	dirp
 *	name
 *	credp
 *	vattrp
 *	filep
 * Returns:
 *	Returns ...
 * Preconditions:
 *	precond(dirp)
 *	precond(name)
 *	precond(credp)
 */
int
kmod_getattrname(cfsd_kmod_object_t *kmod_object_p, cfs_fid_t *dirp,
	const char *name, dl_cred_t *credp, vattr_t *vattrp, cfs_fid_t *filep)
{
	cachefsio_getattrname_arg_t info;
	cachefsio_getattrname_return_t ret;
	int error = 0;
	int xx;

	dbug_enter("kmod_getattrname");
	dbug_precond(kmod_object_p);

	dbug_precond(dirp);
	dbug_precond(name);
	dbug_precond(credp);

	info.cg_dir = *dirp;
	dbug_assert(strlen(name) < (size_t)MAXNAMELEN);
	strlcpy(info.cg_name, name, sizeof (info.cg_name));
	copy_cred(&info.cg_cred, credp);

	xx = kmod_doioctl(kmod_object_p, CFSDCMD_GETATTRNAME, &info,
	    sizeof (info), &ret, sizeof (ret));
	if (xx)
		error = errno;

	dbug_print(("ioctl", "returns %d, error %d", xx, error));
	kmod_format_fid(kmod_object_p, dirp);
	dbug_print(("ioctl", "   dir fid \"%s\"", kmod_object_p->i_fidbuf));
	dbug_print(("ioctl", "   name '%s'", info.cg_name));
	kmod_print_cred(credp);
	if (xx == 0) {
		ret.cg_attr.va_mask = AT_ALL;
		kmod_print_attr(&ret.cg_attr);
		kmod_format_fid(kmod_object_p, &ret.cg_fid);
		dbug_print(("ioctl", "   file fid \"%s\"",
		    kmod_object_p->i_fidbuf));
		if (vattrp)
			*vattrp = ret.cg_attr;
		if (filep)
			*filep = ret.cg_fid;
	}
	dbug_leave("kmod_getattrname");
	return (error);
}

/*
 * ------------------------------------------------------------
 *			kmod_create
 *
 * Description:
 * Arguments:
 *	dirp
 *	namep
 *	vattrp
 *	exclusive
 *	mode
 *	credp
 *	newfidp
 *	mtimep
 *	ctimep
 * Returns:
 *	Returns ...
 * Preconditions:
 *	precond(dirp)
 *	precond(namep)
 *	precond(vattrp)
 *	precond(credp)
 */
int
kmod_create(cfsd_kmod_object_t *kmod_object_p,
	cfs_fid_t *dirp,
	const char *namep,
	const cfs_cid_t *cidp,
	vattr_t *vattrp,
	int exclusive,
	int mode,
	dl_cred_t *credp,
	cfs_fid_t *newfidp,
	cfs_timestruc_t *ctimep,
	cfs_timestruc_t *mtimep)
{
	cachefsio_create_arg_t info;
	cachefsio_create_return_t ret;
	int error = 0;
	int xx;

	dbug_enter("kmod_create");
	dbug_precond(kmod_object_p);

	dbug_precond(dirp);
	dbug_precond(namep);
	dbug_precond(vattrp);
	dbug_precond(credp);

	info.cr_backfid = *dirp;
	dbug_assert(strlen(namep) < (size_t)MAXNAMELEN);
	strlcpy(info.cr_name, namep, sizeof (info.cr_name));
	if (cidp) {
		info.cr_cid = *cidp;
	} else {
		info.cr_cid.cid_fileno = 0;
		info.cr_cid.cid_flags = 0;
	}
	info.cr_va = *vattrp;
	info.cr_exclusive = exclusive;
	info.cr_mode = mode;
	copy_cred(&info.cr_cred, credp);

	xx = kmod_doioctl(kmod_object_p, CFSDCMD_CREATE, &info, sizeof (info),
	    &ret, sizeof (ret));
	if (xx)
		error = errno;

	dbug_print(("ioctl", "returns %d, error %d", xx, error));
	kmod_format_fid(kmod_object_p, dirp);
	dbug_print(("ioctl", "   dir fid \"%s\"", kmod_object_p->i_fidbuf));
	dbug_print(("ioctl", "   name '%s', exclusive %d, mode 0%o",
	    namep, exclusive, mode));
	kmod_print_attr(vattrp);
	kmod_print_cred(credp);
	if (xx == 0) {
		if (newfidp)
			*newfidp = ret.cr_newfid;
		if (ctimep)
			*ctimep = ret.cr_ctime;
		if (mtimep)
			*mtimep = ret.cr_mtime;
		kmod_format_fid(kmod_object_p, &ret.cr_newfid);
		dbug_print(("ioctl", "   created file fid \"%s\"",
		    kmod_object_p->i_fidbuf));
		dbug_print(("ioctl", "   ctime %x %x",
		    ret.cr_ctime.tv_sec, ret.cr_ctime.tv_nsec));
		dbug_print(("ioctl", "   mtime %x %x",
		    ret.cr_mtime.tv_sec, ret.cr_mtime.tv_nsec));
	}
	dbug_leave("kmod_create");
	return (error);
}

/*
 * ------------------------------------------------------------
 *			kmod_pushback
 *
 * Description:
 * Arguments:
 *	filep
 *	fidp
 *	credp
 * Returns:
 *	Returns ...
 * Preconditions:
 *	precond(filep)
 *	precond(fidp)
 *	precond(credp)
 */
int
kmod_pushback(cfsd_kmod_object_t *kmod_object_p,
	cfs_cid_t *filep,
	cfs_fid_t *fidp,
	dl_cred_t *credp,
	cfs_timestruc_t *ctimep,
	cfs_timestruc_t *mtimep,
	int update)
{
	cachefsio_pushback_arg_t info;
	cachefsio_pushback_return_t ret;
	int error = 0;
	int xx;

	dbug_enter("kmod_pushback");
	dbug_precond(kmod_object_p);

	dbug_precond(filep);
	dbug_precond(fidp);
	dbug_precond(credp);

	/* note: update is no longer used */

	info.pb_cid = *filep;
	info.pb_fid = *fidp;
	copy_cred(&info.pb_cred, credp);

	xx = kmod_doioctl(kmod_object_p, CFSDCMD_PUSHBACK, &info, sizeof (info),
	    &ret, sizeof (ret));
	if (xx)
		error = errno;

	dbug_print(("ioctl", "returns %d, error %d", xx, error));
	dbug_print(("ioctl", "   cid %08x", filep->cid_fileno));
	kmod_format_fid(kmod_object_p, fidp);
	dbug_print(("ioctl", "   fid \"%s\"", kmod_object_p->i_fidbuf));
	kmod_print_cred(credp);
	if (xx == 0) {
		if (ctimep)
			*ctimep = ret.pb_ctime;
		if (mtimep)
			*mtimep = ret.pb_mtime;
		dbug_print(("ioctl", "   ctime %x %x",
		    ret.pb_ctime.tv_sec, ret.pb_ctime.tv_nsec));
		dbug_print(("ioctl", "   mtime %x %x",
		    ret.pb_mtime.tv_sec, ret.pb_mtime.tv_nsec));
	}
	dbug_leave("kmod_pushback");
	return (error);
}


/*
 * ------------------------------------------------------------
 *			kmod_rename
 *
 * Description:
 * Arguments:
 *	olddir
 *	oldname
 *	newdir
 *	newname
 *	credp
 * Returns:
 *	Returns ...
 * Preconditions:
 *	precond(olddir)
 *	precond(oldname)
 *	precond(newdir)
 *	precond(newname)
 *	precond(credp)
 */
int
kmod_rename(cfsd_kmod_object_t *kmod_object_p,
	cfs_fid_t *olddir,
	const char *oldname,
	cfs_fid_t *newdir,
	const char *newname,
	const cfs_cid_t *cidp,
	dl_cred_t *credp,
	cfs_timestruc_t *ctimep,
	cfs_timestruc_t *delctimep,
	const cfs_cid_t *delcidp)
{
	cachefsio_rename_arg_t info;
	cachefsio_rename_return_t ret;
	int error = 0;
	int xx;

	dbug_enter("kmod_rename");
	dbug_precond(kmod_object_p);

	dbug_precond(olddir);
	dbug_precond(oldname);
	dbug_precond(newdir);
	dbug_precond(newname);
	dbug_precond(credp);
	dbug_precond(ctimep);

	info.rn_olddir = *olddir;
	dbug_assert(strlen(oldname) < (size_t)MAXNAMELEN);
	strlcpy(info.rn_oldname, oldname, sizeof (info.rn_oldname));
	info.rn_newdir = *newdir;
	dbug_assert(strlen(newname) < (size_t)MAXNAMELEN);
	strlcpy(info.rn_newname, newname, sizeof (info.rn_newname));
	info.rn_cid = *cidp;
	copy_cred(&info.rn_cred, credp);
	info.rn_del_getctime = delctimep ? 1 : 0;
	info.rn_del_cid = *delcidp;

	xx = kmod_doioctl(kmod_object_p, CFSDCMD_RENAME, &info, sizeof (info),
	    &ret, sizeof (ret));
	if (xx)
		error = errno;

	dbug_print(("ioctl", "returns %d, error %d", xx, error));
	kmod_format_fid(kmod_object_p, olddir);
	dbug_print(("ioctl", "   old dir fid \"%s\"", kmod_object_p->i_fidbuf));
	kmod_format_fid(kmod_object_p, newdir);
	dbug_print(("ioctl", "   new dir fid \"%s\"", kmod_object_p->i_fidbuf));
	dbug_print(("ioctl", "   old name '%s'  new name '%s'",
	    oldname, newname));
	kmod_print_cred(credp);
	if (xx == 0) {
		*ctimep = ret.rn_ctime;
		dbug_print(("ioctl", "   ctime %x %x",
		    ctimep->tv_sec, ctimep->tv_nsec));
		if (delctimep) {
			*delctimep = ret.rn_del_ctime;
			dbug_print(("ioctl", "   del ctime %x %x",
			    delctimep->tv_sec, delctimep->tv_nsec));
		}
	}
	dbug_leave("kmod_rename");
	return (error);
}

/*
 * ------------------------------------------------------------
 *			kmod_setattr
 *
 * Description:
 * Arguments:
 *	fidp
 *	vattrp
 *	flags
 *	credp
 * Returns:
 *	Returns ...
 * Preconditions:
 *	precond(fidp)
 *	precond(vattrp)
 *	precond(credp)
 */
int
kmod_setattr(cfsd_kmod_object_t *kmod_object_p,
	cfs_fid_t *fidp,
	const cfs_cid_t *cidp,
	vattr_t *vattrp,
	int flags,
	dl_cred_t *credp,
	cfs_timestruc_t *ctimep,
	cfs_timestruc_t *mtimep)
{
	cachefsio_setattr_arg_t info;
	cachefsio_setattr_return_t ret;
	int error = 0;
	int xx;

	dbug_enter("kmod_setattr");
	dbug_precond(kmod_object_p);

	dbug_precond(fidp);
	dbug_precond(cidp);
	dbug_precond(vattrp);
	dbug_precond(credp);
	dbug_precond(ctimep);
	dbug_precond(mtimep);

	info.sa_backfid = *fidp;
	info.sa_cid = *cidp;
	info.sa_vattr = *vattrp;
	info.sa_flags = flags;
	copy_cred(&info.sa_cred, credp);

	xx = kmod_doioctl(kmod_object_p, CFSDCMD_SETATTR, &info, sizeof (info),
	    &ret, sizeof (ret));
	if (xx)
		error = errno;

	dbug_print(("ioctl", "returns %d, error %d", xx, error));
	dbug_print(("ioctl", "   flags 0x%x", flags));
	kmod_format_fid(kmod_object_p, fidp);
	dbug_print(("ioctl", "   fid \"%s\"", kmod_object_p->i_fidbuf));
	kmod_print_attr(vattrp);
	kmod_print_cred(credp);
	if (xx == 0) {
		*ctimep = ret.sa_ctime;
		*mtimep = ret.sa_mtime;
		dbug_print(("ioctl", "   ctime %x %x", ctimep->tv_sec,
		    ctimep->tv_nsec));
		dbug_print(("ioctl", "   mtime %x %x", mtimep->tv_sec,
		    mtimep->tv_nsec));
	}
	dbug_leave("kmod_setattr");
	return (error);
}

/*
 * ------------------------------------------------------------
 *			kmod_setsecattr
 *
 * Description:
 * Arguments:
 *	fidp
 *	aclcnt
 *	dfaclcnt
 *	acl
 *	flags
 *	credp
 * Returns:
 *	Returns ...
 * Preconditions:
 *	precond(fidp)
 *	precond(acl)
 *	precond(credp)
 *	precond(aclcnt + dfaclcnt <= MAX_ACL_ENTRIES)
 */
int
kmod_setsecattr(cfsd_kmod_object_t *kmod_object_p,
	cfs_fid_t *fidp,
	const cfs_cid_t *cidp,
	ulong_t mask,
	int aclcnt,
	int dfaclcnt,
	const aclent_t *acl,
	dl_cred_t *credp,
	cfs_timestruc_t *ctimep,
	cfs_timestruc_t *mtimep)
{
	cachefsio_setsecattr_arg_t info;
	cachefsio_setsecattr_return_t ret;
	int error = 0;
	int xx;

	dbug_enter("kmod_setsecattr");
	dbug_precond(kmod_object_p);

	dbug_precond(fidp);
	dbug_precond(cidp);
	dbug_precond(acl);
	dbug_precond(credp);
	dbug_precond(ctimep);
	dbug_precond(mtimep);
	dbug_precond(aclcnt + dfaclcnt <= MAX_ACL_ENTRIES);

	info.sc_backfid = *fidp;
	info.sc_cid = *cidp;
	info.sc_mask = mask;
	info.sc_aclcnt = aclcnt;
	info.sc_dfaclcnt = dfaclcnt;
	memcpy(&info.sc_acl, acl, (aclcnt + dfaclcnt) * sizeof (aclent_t));
	copy_cred(&info.sc_cred, credp);

	xx = kmod_doioctl(kmod_object_p, CFSDCMD_SETSECATTR, &info,
	    sizeof (info), &ret, sizeof (ret));
	if (xx)
		error = errno;

	dbug_print(("ioctl", "returns %d, error %d", xx, error));
	kmod_format_fid(kmod_object_p, fidp);
	dbug_print(("ioctl", "   fid \"%s\"", kmod_object_p->i_fidbuf));
	dbug_print(("ioctl", "   aclcnt %d dfaclcnt %d", aclcnt, dfaclcnt));
	kmod_print_cred(credp);
	if (xx == 0) {
		*ctimep = ret.sc_ctime;
		*mtimep = ret.sc_mtime;
		dbug_print(("ioctl", "   ctime %x %x", ctimep->tv_sec,
		    ctimep->tv_nsec));
		dbug_print(("ioctl", "   mtime %x %x", mtimep->tv_sec,
		    mtimep->tv_nsec));
	}
	dbug_leave("kmod_setsecattr");
	return (error);
}

/*
 * ------------------------------------------------------------
 *			kmod_remove
 *
 * Description:
 * Arguments:
 *	fidp
 *	namep
 *	credp
 *	ctimep
 * Returns:
 *	Returns ...
 * Preconditions:
 *	precond(fidp)
 *	precond(namep)
 *	precond(credp)
 */
int
kmod_remove(cfsd_kmod_object_t *kmod_object_p,
	const cfs_fid_t *fidp,
	const cfs_cid_t *cidp,
	const char *namep,
	const dl_cred_t *credp,
	cfs_timestruc_t *ctimep)
{
	cachefsio_remove_t info;
	int len;
	int error = 0;
	int xx;

	dbug_enter("kmod_remove");
	dbug_precond(kmod_object_p);

	dbug_precond(fidp);
	dbug_precond(cidp);
	dbug_precond(namep);
	dbug_precond(credp);

	info.rm_fid = *fidp;
	info.rm_cid = *cidp;
	dbug_assert(strlen(namep) < (size_t)MAXNAMELEN);
	strlcpy(info.rm_name, namep, sizeof (info.rm_name));
	copy_cred(&info.rm_cred, credp);
	info.rm_getctime = ctimep ? 1 : 0;

	if (ctimep)
		len = sizeof (*ctimep);
	else
		len = 0;

	xx = kmod_doioctl(kmod_object_p, CFSDCMD_REMOVE, &info, sizeof (info),
	    ctimep, len);
	if (xx)
		error = errno;

	dbug_print(("ioctl", "returns %d, error %d", xx, error));
	kmod_format_fid(kmod_object_p, fidp);
	dbug_print(("ioctl", "   fid '%s'", kmod_object_p->i_fidbuf));
	dbug_print(("ioctl", "   name '%s'", namep));
	kmod_print_cred(credp);
	if ((xx == 0) && ctimep) {
		dbug_print(("ioctl", "   ctime %x %x", ctimep->tv_sec,
		    ctimep->tv_nsec));
	}
	dbug_leave("kmod_remove");
	return (error);
}

/*
 * ------------------------------------------------------------
 *			kmod_link
 *
 * Description:
 * Arguments:
 *	dirfidp
 *	namep
 *	filefidp
 *	credp
 *	ctimep
 * Returns:
 *	Returns ...
 * Preconditions:
 *	precond(dirfidp)
 *	precond(namep)
 *	precond(filefidp)
 *	precond(credp)
 */
int
kmod_link(cfsd_kmod_object_t *kmod_object_p,
	const cfs_fid_t *dirfidp,
	const char *namep,
	const cfs_fid_t *filefidp,
	const cfs_cid_t *cidp,
	const dl_cred_t *credp,
	cfs_timestruc_t *ctimep)
{
	cachefsio_link_t info;
	int error = 0;
	int xx;

	dbug_enter("kmod_link");
	dbug_precond(kmod_object_p);

	dbug_precond(dirfidp);
	dbug_precond(namep);
	dbug_precond(filefidp);
	dbug_precond(cidp);
	dbug_precond(credp);
	dbug_precond(ctimep);

	info.ln_dirfid = *dirfidp;
	dbug_assert(strlen(namep) < (size_t)MAXNAMELEN);
	strlcpy(info.ln_name, namep, sizeof (info.ln_name));
	info.ln_filefid = *filefidp;
	info.ln_cid = *cidp;
	copy_cred(&info.ln_cred, credp);

	xx = kmod_doioctl(kmod_object_p, CFSDCMD_LINK, &info, sizeof (info),
	    ctimep, sizeof (*ctimep));
	if (xx)
		error = errno;

	dbug_print(("ioctl", "returns %d, error %d", xx, error));
	kmod_format_fid(kmod_object_p, dirfidp);
	dbug_print(("ioctl", "   dir fid '%s'", kmod_object_p->i_fidbuf));
	dbug_print(("ioctl", "   name '%s'", namep));
	kmod_format_fid(kmod_object_p, filefidp);
	dbug_print(("ioctl", "   file fid '%s'", kmod_object_p->i_fidbuf));
	kmod_print_cred(credp);
	if (xx == 0) {
		dbug_print(("ioctl", "   ctime %x %x", ctimep->tv_sec,
		    ctimep->tv_nsec));
	}
	dbug_leave("kmod_link");
	return (error);
}

/*
 * ------------------------------------------------------------
 *			kmod_mkdir
 *
 * Description:
 * Arguments:
 *	dirfidp
 *	namep
 *	vattrp
 *	credp
 *	newfidp
 * Returns:
 *	Returns ...
 * Preconditions:
 *	precond(dirfidp)
 *	precond(namep)
 *	precond(vattrp)
 *	precond(credp)
 *	precond(newfidp)
 */
int
kmod_mkdir(cfsd_kmod_object_t *kmod_object_p,
	const cfs_fid_t *dirfidp,
	const char *namep,
	const cfs_cid_t *cidp,
	const vattr_t *vattrp,
	const dl_cred_t *credp,
	cfs_fid_t *newfidp)
{
	cachefsio_mkdir_t info;
	int error = 0;
	int xx;

	dbug_enter("kmod_mkdir");
	dbug_precond(kmod_object_p);

	dbug_precond(dirfidp);
	dbug_precond(namep);
	dbug_precond(cidp);
	dbug_precond(vattrp);
	dbug_precond(credp);
	dbug_precond(newfidp);

	info.md_dirfid = *dirfidp;
	dbug_assert(strlen(namep) < (size_t)MAXNAMELEN);
	strlcpy(info.md_name, namep, sizeof (info.md_name));
	info.md_cid = *cidp;
	info.md_vattr = *vattrp;
	copy_cred(&info.md_cred, credp);

	xx = kmod_doioctl(kmod_object_p, CFSDCMD_MKDIR, &info, sizeof (info),
	    newfidp, sizeof (*newfidp));
	if (xx)
		error = errno;

	dbug_print(("ioctl", "returns %d, error %d", xx, error));
	kmod_format_fid(kmod_object_p, dirfidp);
	dbug_print(("ioctl", "   dir fid '%s'", kmod_object_p->i_fidbuf));
	dbug_print(("ioctl", "   name '%s'", namep));
	kmod_print_attr(vattrp);
	kmod_print_cred(credp);
	if (xx == 0) {
		kmod_format_fid(kmod_object_p, newfidp);
		dbug_print(("ioctl", "   file fid '%s'",
		    kmod_object_p->i_fidbuf));
	}
	dbug_leave("kmod_mkdir");
	return (error);
}

/*
 * ------------------------------------------------------------
 *			kmod_rmdir
 *
 * Description:
 * Arguments:
 *	dirfidp
 *	namep
 *	credp
 * Returns:
 *	Returns ...
 * Preconditions:
 *	precond(dirfidp)
 *	precond(namep)
 *	precond(credp)
 */
int
kmod_rmdir(cfsd_kmod_object_t *kmod_object_p,
	const cfs_fid_t *dirfidp,
	const char *namep,
	const dl_cred_t *credp)
{
	cachefsio_rmdir_t info;
	int error = 0;
	int xx;

	dbug_enter("kmod_rmdir");
	dbug_precond(kmod_object_p);

	dbug_precond(dirfidp);
	dbug_precond(namep);
	dbug_precond(credp);

	info.rd_dirfid = *dirfidp;
	dbug_assert(strlen(namep) < (size_t)MAXNAMELEN);
	strlcpy(info.rd_name, namep, sizeof (info.rd_name));
	copy_cred(&info.rd_cred, credp);

	xx = kmod_doioctl(kmod_object_p, CFSDCMD_RMDIR, &info, sizeof (info),
	    NULL, 0);
	if (xx)
		error = errno;

	dbug_print(("ioctl", "returns %d, error %d", xx, error));
	kmod_format_fid(kmod_object_p, dirfidp);
	dbug_print(("ioctl", "   dir fid '%s'", kmod_object_p->i_fidbuf));
	dbug_print(("ioctl", "   name '%s'", namep));
	kmod_print_cred(credp);
	dbug_leave("kmod_rmdir");
	return (error);
}

/*
 * ------------------------------------------------------------
 *			kmod_symlink
 *
 * Description:
 * Arguments:
 *	dirfidp
 *	namep
 *	linkvalp
 *	vattrp
 *	credp
 *	ctimep
 *	mtimep
 * Returns:
 *	Returns ...
 * Preconditions:
 *	precond(dirfidp)
 *	precond(namep)
 *	precond(linkvalp)
 *	precond(vattrp)
 *	precond(credp)
 *	precond(ctimep)
 *	precond(mtimep)
 */
int
kmod_symlink(cfsd_kmod_object_t *kmod_object_p,
	const cfs_fid_t *dirfidp,
	const char *namep,
	const cfs_cid_t *cidp,
	const char *linkvalp,
	const vattr_t *vattrp,
	const dl_cred_t *credp,
	cfs_fid_t *newfidp,
	cfs_timestruc_t *ctimep,
	cfs_timestruc_t *mtimep)
{
	cachefsio_symlink_arg_t info;
	cachefsio_symlink_return_t ret;
	int error = 0;
	int xx;

	dbug_enter("kmod_symlink");
	dbug_precond(kmod_object_p);

	dbug_precond(dirfidp);
	dbug_precond(namep);
	dbug_precond(cidp);
	dbug_precond(linkvalp);
	dbug_precond(vattrp);
	dbug_precond(credp);
	dbug_precond(newfidp);
	dbug_precond(ctimep);
	dbug_precond(mtimep);

	info.sy_dirfid = *dirfidp;
	dbug_assert(strlen(namep) < (size_t)MAXNAMELEN);
	strlcpy(info.sy_name, namep, sizeof (info.sy_name));
	dbug_assert(strlen(linkvalp) < (size_t)MAXPATHLEN);
	info.sy_cid = *cidp;
	strlcpy(info.sy_link, linkvalp, sizeof (info.sy_link));
	info.sy_vattr = *vattrp;
	copy_cred(&info.sy_cred, credp);

	xx = kmod_doioctl(kmod_object_p, CFSDCMD_SYMLINK, &info, sizeof (info),
	    &ret, sizeof (ret));
	if (xx)
		error = errno;

	dbug_print(("ioctl", "returns %d, error %d", xx, error));
	kmod_format_fid(kmod_object_p, dirfidp);
	dbug_print(("ioctl", "   dir fid '%s'", kmod_object_p->i_fidbuf));
	dbug_print(("ioctl", "   name '%s'", namep));
	dbug_print(("ioctl", "   link '%s'", linkvalp));
	kmod_print_attr(vattrp);
	kmod_print_cred(credp);
	if (xx == 0) {
		*ctimep = ret.sy_ctime;
		*mtimep = ret.sy_mtime;
		*newfidp = ret.sy_newfid;
		dbug_print(("ioctl", "   ctime %x %x", ctimep->tv_sec,
		    ctimep->tv_nsec));
		dbug_print(("ioctl", "   mtime %x %x", mtimep->tv_sec,
		    mtimep->tv_nsec));
		kmod_format_fid(kmod_object_p, newfidp);
		dbug_print(("ioctl", "   child fid '%s'",
		    kmod_object_p->i_fidbuf));
	}
	dbug_leave("kmod_symlink");
	return (error);
}
#ifndef DBUG_OFF
/*
 * ------------------------------------------------------------
 *			kmod_format_fid
 *
 * Description:
 * Arguments:
 *	fidp
 * Returns:
 * Preconditions:
 *	precond(fidp)
 */
void
kmod_format_fid(cfsd_kmod_object_t *kmod_object_p, const cfs_fid_t *fidp)
{
	uint_t val;
	int index;
	char format[10];
	kmod_object_p->i_fidbuf[0] = '\0';

	for (index = 0; index < (int)fidp->fid_len; index += sizeof (uint_t)) {
		memcpy(&val, &fidp->fid_data[index], sizeof (uint_t));
		snprintf(format, sizeof (format), "%08x ", val);
		strlcat(kmod_object_p->i_fidbuf, format,
		    sizeof (kmod_object_p->i_fidbuf));
	}
}

/*
 * ------------------------------------------------------------
 *			kmod_print_cred
 *
 * Description:
 * Arguments:
 *	credp
 * Returns:
 * Preconditions:
 *	precond(credp)
 */
void
kmod_print_cred(const dl_cred_t *credp)
{
	char buf[100];
	char format[10];
	int xx;

	dbug_enter("kmod_print_cred");
	dbug_precond(credp);

	buf[0] = '\0';
	dbug_print(("ioctl", "credentials"));
	dbug_print(("ioctl", "  uid %d, gid %d",
	    credp->cr_uid, credp->cr_gid));
	dbug_print(("ioctl", "  ruid %d, rgid %d, suid %d, sgid %d",
	    credp->cr_ruid, credp->cr_rgid,
	    credp->cr_suid, credp->cr_sgid));

	for (xx = 0; xx < credp->cr_ngroups; xx++) {
		snprintf(format, sizeof (format), " %d", credp->cr_groups[xx]);
		strlcat(buf, format, sizeof (buf));
	}

	dbug_print(("ioctl", "  ngroups %d,  %s", credp->cr_ngroups, buf));
	dbug_leave("kmod_print_cred");
}

/*
 * ------------------------------------------------------------
 *			kmod_print_attr
 *
 * Description:
 * Arguments:
 *	vattrp
 * Returns:
 * Preconditions:
 *	precond(vattrp)
 */
void
kmod_print_attr(const vattr_t *vp)
{
	dbug_enter("kmod_print_attr");
	dbug_precond(vp);

	dbug_print(("ioctl", "attributes"));
	dbug_print(("ioctl", "  mask 0x%x", vp->va_mask));
	if (vp->va_mask & AT_TYPE)
		dbug_print(("ioctl", "  type %d", vp->va_type));
	if (vp->va_mask & AT_MODE)
		dbug_print(("ioctl", "  mode 0%o", vp->va_mode));
	if (vp->va_mask & AT_UID)
		dbug_print(("ioctl", "  uid %d", vp->va_uid));
	if (vp->va_mask & AT_GID)
		dbug_print(("ioctl", "  gid %d", vp->va_gid));
	if (vp->va_mask & AT_FSID)
		dbug_print(("ioctl", "  fsid %08x", vp->va_fsid));
	if (vp->va_mask & AT_NODEID)
		dbug_print(("ioctl", "  nodeid %08x", vp->va_nodeid));
	if (vp->va_mask & AT_NLINK)
		dbug_print(("ioctl", "  nlink %d", vp->va_nlink));
	if (vp->va_mask & AT_SIZE)
		dbug_print(("ioctl", "  size %d", vp->va_size));
	if (vp->va_mask & AT_ATIME)
		dbug_print(("ioctl", "  atime %08x %08x",
		    vp->va_atime.tv_sec, vp->va_atime.tv_nsec));
	if (vp->va_mask & AT_MTIME)
		dbug_print(("ioctl", "  mtime %08x %08x",
		    vp->va_mtime.tv_sec, vp->va_mtime.tv_nsec));
	if (vp->va_mask & AT_CTIME)
		dbug_print(("ioctl", "  ctime %08x %08x",
		    vp->va_ctime.tv_sec, vp->va_ctime.tv_nsec));
	if (vp->va_mask & AT_RDEV)
		dbug_print(("ioctl", "  rdev %08x", vp->va_rdev));
	if (vp->va_mask & AT_BLKSIZE)
		dbug_print(("ioctl", "  blksize %08x", vp->va_blksize));
	if (vp->va_mask & AT_NBLOCKS)
		dbug_print(("ioctl", "  nblocks %d", vp->va_nblocks));
	if (vp->va_mask & AT_SEQ)
		dbug_print(("ioctl", "  seq %d", vp->va_seq));
	dbug_leave("kmod_print_attr");
}
#endif /* DBUG_OFF */
/*
 *			kmod_doioctl
 *
 * Description:
 *	Helper routine for others in this file.  Just packages up
 *	arguments and does the ioctl operation.
 * Arguments:
 *	cmd
 *	sdata
 *	slen
 *	rdata
 *	rlen
 * Returns:
 *	Returns the result of the ioctl operation.
 * Preconditions:
 */
int
kmod_doioctl(cfsd_kmod_object_t *kmod_object_p,
	enum cfsdcmd_cmds cmd,
	void *sdata,
	int slen,
	void *rdata,
	int rlen)
{
	cachefsio_dcmd_t dcmd;
	int xx;

	dbug_enter("kmod_doioctl");
	dbug_precond(kmod_object_p);
	dcmd.d_cmd = cmd;
	dcmd.d_sdata = sdata;
	dcmd.d_slen = slen;
	dcmd.d_rdata = rdata;
	dcmd.d_rlen = rlen;
	dbug_print(("ioctl", "about to do cmd = %d", cmd));
	xx = ioctl(kmod_object_p->i_fd, CACHEFSIO_DCMD, &dcmd);
	if (xx) {
		dbug_print(("ioctl", "ioctl errno = %d", errno));
	}
	dbug_leave("kmod_doioctl");
	return (xx);
}
