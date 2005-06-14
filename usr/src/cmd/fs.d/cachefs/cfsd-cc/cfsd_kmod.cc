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
//			cfsd_kmod.cc
//
// Source file for the cfsd_kmod class.
//

#pragma ident	"%Z%%M%	%I%	%E% SMI"
// Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
// Use is subject to license terms.

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/fcntl.h>
#include <sys/cred.h>
#include <sys/vnode.h>
#include <sys/vfs.h>
#include <rw/cstring.h>
#include <rw/regexp.h>
#include <rw/rstream.h>
#include <rw/tpdlist.h>
#include <sys/fs/cachefs_fs.h>
#include <sys/fs/cachefs_dlog.h>
#include <sys/fs/cachefs_ioctl.h>
#include <mdbug-cc/mdbug.h>
#include "cfsd_kmod.h"

// -----------------------------------------------------------------
//
//			cfsd_kmod::cfsd_kmod
//
// Description:
// Arguments:
// Returns:
// Preconditions:


cfsd_kmod::cfsd_kmod() : i_path("none")
{
	dbug_enter("cfsd_kmod::cfsd_kmod");

	i_fd = -1;
}

// -----------------------------------------------------------------
//
//			cfsd_kmod::~cfsd_kmod
//
// Description:
// Arguments:
// Returns:
// Preconditions:


cfsd_kmod::~cfsd_kmod()
{
	dbug_enter("cfsd_kmod::~cfsd_kmod");

	// clean up old stuff
	kmod_shutdown();
}

// -----------------------------------------------------------------
//
//			cfsd_kmod::kmod_setup
//
// Description:
// Arguments:
//	path
// Returns:
//	Returns ...
// Preconditions:
//	precond(path)

int
cfsd_kmod::kmod_setup(const char *path)
{
	dbug_enter("cfsd_kmod::kmod_setup");
	dbug_precond(path);

	// clean up old stuff
	kmod_shutdown();

	// try to open the file
	i_fd = open(path, O_RDONLY);

	// return result
	int xx;
	int error;
	if (i_fd == -1) {
		xx = errno;
		dbug_print("err", ("open of %s failed %d", path, xx));
	} else {
		xx = 0;
		i_path = path;
		dbug_print("info", ("opened %s on fd %d", path, i_fd));

		// tell the cachefs kmod we are here
		xx = i_doioctl(CFSDCMD_DAEMONID, NULL, 0, NULL, 0);
		if (xx) {
			error = errno;
			dbug_print("ioctl", ("daemonid error %d", error));
		}
	}

	return (xx);
}

//
//			kmod_shutdown
//
// Description:
// Arguments:
// Returns:
// Preconditions:

void
cfsd_kmod::kmod_shutdown()
{
	dbug_enter("kmod_shutdown");

	// close down the old fd if necessary
	if (i_fd >= 0)
		close(i_fd);
	i_fd = -1;
}

// -----------------------------------------------------------------
//
//			cfsd_kmod::kmod_xwait
//
// Description:
// Arguments:
// Returns:
//	Returns ...
// Preconditions:

int
cfsd_kmod::kmod_xwait()
{
	dbug_enter("cfsd_kmod::kmod_xwait");
	int xx;
	int error = 0;

	xx = i_doioctl(CFSDCMD_XWAIT, NULL, 0, NULL, 0);
	if (xx)
		error = errno;
	dbug_print("ioctl", ("returns %d, error %d", xx, error));
	return (error);
}

// -----------------------------------------------------------------
//
//			cfsd_kmod::kmod_stateget
//
// Description:
// Arguments:
// Returns:
//	Returns ...
// Preconditions:

int
cfsd_kmod::kmod_stateget()
{
	dbug_enter("cfsd_kmod::kmod_stateget");
	int state;
	int xx;
	int error = 0;

	xx = i_doioctl(CFSDCMD_STATEGET, NULL, 0, &state, sizeof (state));
	dbug_print("ioctl", ("returns %d, state %d", xx, state));
	if (xx == -1) {
		// XXX do what?
		dbug_assert(0);
	}
	return (state);
}

// -----------------------------------------------------------------
//
//			cfsd_kmod::kmod_stateset
//
// Description:
// Arguments:
//	state
// Returns:
//	Returns ...
// Preconditions:

int
cfsd_kmod::kmod_stateset(int state)
{
	dbug_enter("cfsd_kmod::kmod_stateset");
	int xx;
	int error = 0;
	xx = i_doioctl(CFSDCMD_STATESET, &state, sizeof (state), NULL, 0);
	if (xx)
		error = errno;
	dbug_print("ioctl", ("returns %d, state set to %d", xx, state));
	return (error);
}

// -----------------------------------------------------------------
//
//			cfsd_kmod::kmod_exists
//
// Description:
// Arguments:
//	cidp
// Returns:
//	Returns ...
// Preconditions:
//	precond(cidp)

int
cfsd_kmod::kmod_exists(cfs_cid *cidp)
{
	dbug_enter("cfsd_kmod::kmod_exists");
	dbug_precond(cidp);
	int xx;
	int error = 0;
	xx = i_doioctl(CFSDCMD_EXISTS, cidp, sizeof (cfs_cid), NULL, 0);
	if (xx)
		error = errno;
	dbug_print("ioctl", ("returns %d, error %d", xx, error));
	dbug_print("ioctl", ("   cid %08x", cidp->cid_fileno));
	return (error);
}

// -----------------------------------------------------------------
//
//			cfsd_kmod::kmod_lostfound
//
// Description:
// Arguments:
//	cidp
// Returns:
//	Returns ...
// Preconditions:
//	precond(cidp)

int
cfsd_kmod::kmod_lostfound(cfs_cid *cidp, const char *namep, char *newnamep)
{
	dbug_enter("cfsd_kmod::kmod_lostfound");
	dbug_precond(cidp);
	dbug_precond(namep);
	dbug_precond(newnamep);
	dbug_precond(strlen(namep) <= (MAXNAMELEN - 1));

	cachefsio_lostfound_arg info;
	info.lf_cid = *cidp;
	strcpy(info.lf_name, namep);
	cachefsio_lostfound_return ret;

	int error = 0;
	int xx;
	xx = i_doioctl(CFSDCMD_LOSTFOUND, &info, sizeof (info),
	    &ret, sizeof (ret));
	if (xx)
		error = errno;
	dbug_print("ioctl", ("returns %d, error %d", xx, error));
	dbug_print("ioctl", ("   cid %08x", cidp->cid_fileno));
	dbug_print("ioctl", ("   suggested name '%s'", namep));
	if (xx == 0) {
		dbug_print("ioctl", ("   new name '%s'", ret.lf_name));
		dbug_assert(strlen(ret.lf_name) < MAXNAMELEN);
		if (newnamep)
			strcpy(newnamep, ret.lf_name);
	}
	return (error);
}

// -----------------------------------------------------------------
//
//			cfsd_kmod::kmod_lostfoundall
//
// Description:
// Arguments:
// Returns:
//	Returns ...
// Preconditions:

int
cfsd_kmod::kmod_lostfoundall()
{
	dbug_enter("cfsd_kmod::kmod_lostfoundall");
	int error = 0;
	int xx = -1;
	// xx = ioctl(i_fd, CACHEFSIO_LOSTFOUNDALL, 0);
	if (xx)
		error = errno;
	dbug_print("ioctl", ("returns %d, error %d", xx, error));
	return (error);
}

//
//			cfsd_kmod::kmod_rofs
//
// Description:
// Arguments:
// Returns:
//	Returns ...
// Preconditions:

int
cfsd_kmod::kmod_rofs()
{
	dbug_enter("cfsd_kmod::kmod_rofs");
	int error = 0;
	int xx = -1;
	// xx = ioctl(i_fd, CACHEFSIO_ROFS, 0);
	if (xx)
		error = errno;
	dbug_print("ioctl", ("returns %d, error %d", xx, error));
	return (error);
}

//
//			cfsd_kmod::kmod_rootfid
//
// Description:
//	Fills in fidp with the fid of the root of the file system.
// Arguments:
//	fidp
// Returns:
//	Returns 0 for success, errno value for an error
// Preconditions:
//	precond(fidp)

int
cfsd_kmod::kmod_rootfid(cfs_fid_t *fidp)
{
	dbug_enter("cfsd_kmod::kmod_rootfid");
	dbug_precond(fidp);

	int error = 0;
	int xx;
	xx = i_doioctl(CFSDCMD_ROOTFID, NULL, 0, fidp, sizeof (*fidp));
	if (xx)
		error = errno;
	dbug_print("ioctl", ("returns %d, error %d", xx, error));
	return (error);
}


//
//			cfsd_kmod::kmod_getstats
//
// Description:
// Arguments:
//	gsp
// Returns:
//	Returns ...
// Preconditions:
//	precond(gsp)

int
cfsd_kmod::kmod_getstats(cachefsio_getstats_t *gsp)
{
	dbug_enter("cfsd_kmod::kmod_getstats");

	dbug_precond(gsp);

	int error = 0;
	int xx;
	xx = i_doioctl(CFSDCMD_GETSTATS, NULL, 0, gsp, sizeof (*gsp));
	if (xx)
		error = errno;
	dbug_print("ioctl", ("returns %d, error %d", xx, error));
	dbug_print("ioctl", ("total blocks %d", gsp->gs_total));
	dbug_print("ioctl", ("gc blocks %d", gsp->gs_gc));
	dbug_print("ioctl", ("active blocks %d", gsp->gs_active));
	dbug_print("ioctl", ("packed blocks %d", gsp->gs_packed));
	dbug_print("ioctl", ("free blocks %d", gsp->gs_free));
	dbug_print("ioctl", ("gctime %x", gsp->gs_gctime));
	return (error);
}

// -----------------------------------------------------------------
//
//			cfsd_kmod::kmod_getinfo
//
// Description:
// Arguments:
//	filep
// Returns:
//	Returns ...
// Preconditions:
//	precond(filep)
//	precond(infop)

int
cfsd_kmod::kmod_getinfo(cfs_cid_t *filep, cachefsio_getinfo_t *infop)
{
	dbug_enter("cfsd_kmod::kmod_getinfo");

	dbug_precond(filep);
	dbug_precond(infop);

	int error = 0;
	int xx;
	xx = i_doioctl(CFSDCMD_GETINFO, filep, sizeof (*filep),
	    infop, sizeof (*infop));
	if (xx)
		error = errno;

	dbug_print("ioctl", ("returns %d, error %d", xx, error));
	dbug_print("ioctl", ("   file cid %08x", filep->cid_fileno));
	if (xx == 0) {
		dbug_print("ioctl", ("   modified %d  seq %d",
		    infop->gi_modified, infop->gi_seq));
		dbug_print("ioctl", ("   name \"%s\"", infop->gi_name));
		dbug_print("ioctl", ("   parent cid %08x",
		    infop->gi_pcid.cid_fileno));
		infop->gi_attr.va_mask = AT_ALL;
		i_print_attr(&infop->gi_attr);
	}
	return (error);
}

// -----------------------------------------------------------------
//
//			cfsd_kmod::kmod_cidtofid
//
// Description:
// Arguments:
//	cidp
//	fidp
// Returns:
//	Returns ...
// Preconditions:
//	precond(cidp)
//	precond(fidp)

int
cfsd_kmod::kmod_cidtofid(cfs_cid *cidp, cfs_fid_t *fidp)
{
	dbug_enter("cfsd_kmod::kmod_cidtofid");

	dbug_precond(cidp);
	dbug_precond(fidp);

	int error = 0;
	int xx;
	xx = i_doioctl(CFSDCMD_CIDTOFID, cidp, sizeof (*cidp),
	    fidp, sizeof (*fidp));
	if (xx)
		error = errno;

	dbug_print("ioctl", ("returns %d, error %d", xx, error));
	dbug_print("ioctl", ("   cid %08x", cidp->cid_fileno));
	if (xx == 0) {
		i_format_fid(fidp);
		dbug_print("ioctl", ("   fid \"%s\"", i_fidbuf));
	}
	return (error);
}

// -----------------------------------------------------------------
//
//			cfsd_kmod::kmod_getattrfid
//
// Description:
// Arguments:
//	fidp
//	credp
//	vattrp
// Returns:
//	Returns ...
// Preconditions:
//	precond(fidp)
//	precond(credp)
//	precond(vattrp)

int
cfsd_kmod::kmod_getattrfid(cfs_fid_t *fidp, cred_t *credp, cfs_vattr_t *vattrp)
{
	dbug_enter("cfsd_kmod::kmod_getattrfid");

	dbug_precond(fidp);
	dbug_precond(credp);
	dbug_precond(vattrp);

	cachefsio_getattrfid_t info;
	info.cg_backfid = *fidp;
	int len = sizeof (cred_t) + ((credp->cr_ngroups - 1) * sizeof (gid_t));
	memcpy(&info.cg_cred, credp, len);

	int error = 0;
	int xx;
	xx = i_doioctl(CFSDCMD_GETATTRFID, &info, sizeof (info),
	    vattrp, sizeof (*vattrp));
	if (xx)
		error = errno;

	dbug_print("ioctl", ("returns %d, error %d", xx, error));
	i_format_fid(fidp);
	dbug_print("ioctl", ("   fid \"%s\"", i_fidbuf));
	i_print_cred(credp);
	if (xx == 0) {
		vattrp->va_mask = AT_ALL;
		i_print_attr(vattrp);
	}
	return (error);
}

// -----------------------------------------------------------------
//
//			cfsd_kmod::kmod_getattrname
//
// Description:
// Arguments:
//	dirp
//	name
//	credp
//	vattrp
//	filep
// Returns:
//	Returns ...
// Preconditions:
//	precond(dirp)
//	precond(name)
//	precond(credp)

int
cfsd_kmod::kmod_getattrname(cfs_fid_t *dirp, const char *name, cred_t *credp,
			    cfs_vattr_t *vattrp, cfs_fid_t *filep)
{
	dbug_enter("cfsd_kmod::kmod_getattrname");

	dbug_precond(dirp);
	dbug_precond(name);
	dbug_precond(credp);

	cachefsio_getattrname_arg_t info;
	info.cg_dir = *dirp;
	dbug_assert((strlen(name) + 1) < MAXNAMELEN);
	strcpy(info.cg_name, name);
	int len = sizeof (cred_t) + ((credp->cr_ngroups - 1) * sizeof (gid_t));
	memcpy(&info.cg_cred, credp, len);

	cachefsio_getattrname_return_t ret;
	int error = 0;
	int xx;
	xx = i_doioctl(CFSDCMD_GETATTRNAME, &info, sizeof (info),
	    &ret, sizeof (ret));
	if (xx)
		error = errno;

	dbug_print("ioctl", ("returns %d, error %d", xx, error));
	i_format_fid(dirp);
	dbug_print("ioctl", ("   dir fid \"%s\"", i_fidbuf));
	dbug_print("ioctl", ("   name '%s'", info.cg_name));
	i_print_cred(credp);
	if (xx == 0) {
		ret.cg_attr.va_mask = AT_ALL;
		i_print_attr(&ret.cg_attr);
		i_format_fid(&ret.cg_fid);
		dbug_print("ioctl", ("   file fid \"%s\"", i_fidbuf));
		if (vattrp)
			*vattrp = ret.cg_attr;
		if (filep)
			*filep = ret.cg_fid;
	}
	return (error);
}

// -----------------------------------------------------------------
//
//			cfsd_kmod::kmod_create
//
// Description:
// Arguments:
//	dirp
//	namep
//	vattrp
//	exclusive
//	mode
//	credp
//	newfidp
//	mtimep
//	ctimep
// Returns:
//	Returns ...
// Preconditions:
//	precond(dirp)
//	precond(namep)
//	precond(vattrp)
//	precond(credp)

int
cfsd_kmod::kmod_create(cfs_fid_t *dirp, const char *namep, const cfs_cid_t *cidp,
    cfs_vattr_t *vattrp, int exclusive, int mode, cred_t *credp,
    cfs_fid_t *newfidp, cfs_timestruc_t *ctimep, cfs_timestruc_t *mtimep)
{
	dbug_enter("cfsd_kmod::kmod_create");

	dbug_precond(dirp);
	dbug_precond(namep);
	dbug_precond(vattrp);
	dbug_precond(credp);

	cachefsio_create_arg_t info;
	info.cr_backfid = *dirp;
	dbug_assert(strlen(namep) < MAXNAMELEN);
	strcpy(info.cr_name, namep);
	if (cidp)
		info.cr_cid = *cidp;
	else {
		info.cr_cid.cid_fileno = 0;
		info.cr_cid.cid_flags = 0;
	}
	info.cr_va = *vattrp;
	info.cr_exclusive = exclusive;
	info.cr_mode = mode;
	int len = sizeof (cred_t) + ((credp->cr_ngroups - 1) * sizeof (gid_t));
	memcpy(&info.cr_cred, credp, len);

	cachefsio_create_return_t ret;
	int error = 0;
	int xx;
	xx = i_doioctl(CFSDCMD_CREATE, &info, sizeof (info),
	    &ret, sizeof (ret));
	if (xx)
		error = errno;

	dbug_print("ioctl", ("returns %d, error %d", xx, error));
	i_format_fid(dirp);
	dbug_print("ioctl", ("   dir fid \"%s\"", i_fidbuf));
	dbug_print("ioctl", ("   name '%s', exclusive %d, mode 0%o",
			    namep, exclusive, mode));
	i_print_attr(vattrp);
	i_print_cred(credp);
	if (xx == 0) {
		if (newfidp)
			*newfidp = ret.cr_newfid;
		if (ctimep)
			*ctimep = ret.cr_ctime;
		if (mtimep)
			*mtimep = ret.cr_mtime;
		i_format_fid(&ret.cr_newfid);
		dbug_print("ioctl", ("   created file fid \"%s\"", i_fidbuf));
		dbug_print("ioctl", ("   ctime %x %x",
			ret.cr_ctime.tv_sec, ret.cr_ctime.tv_nsec));
		dbug_print("ioctl", ("   mtime %x %x",
			ret.cr_mtime.tv_sec, ret.cr_mtime.tv_nsec));
	}
	return (error);
}

// -----------------------------------------------------------------
//
//			cfsd_kmod::kmod_pushback
//
// Description:
// Arguments:
//	filep
//	fidp
//	credp
// Returns:
//	Returns ...
// Preconditions:
//	precond(filep)
//	precond(fidp)
//	precond(credp)

int
cfsd_kmod::kmod_pushback(cfs_cid *filep, cfs_fid_t *fidp, cred_t *credp,
    cfs_timestruc_t *ctimep, cfs_timestruc_t *mtimep, int update)
{
	dbug_enter("cfsd_kmod::kmod_pushback");

	dbug_precond(filep);
	dbug_precond(fidp);
	dbug_precond(credp);

	// note: update is no longer used

	cachefsio_pushback_arg_t info;
	info.pb_cid = *filep;
	info.pb_fid = *fidp;
	int len = sizeof (cred_t) + ((credp->cr_ngroups - 1) * sizeof (gid_t));
	memcpy(&info.pb_cred, credp, len);

	cachefsio_pushback_return_t ret;
	int error = 0;
	int xx;
	xx = i_doioctl(CFSDCMD_PUSHBACK, &info, sizeof (info),
	    &ret, sizeof (ret));
	if (xx)
		error = errno;

	dbug_print("ioctl", ("returns %d, error %d", xx, error));
	dbug_print("ioctl", ("   cid %08x", filep->cid_fileno));
	i_format_fid(fidp);
	dbug_print("ioctl", ("   fid \"%s\"", i_fidbuf));
	i_print_cred(credp);
	if (xx == 0) {
		if (ctimep)
			*ctimep = ret.pb_ctime;
		if (mtimep)
			*mtimep = ret.pb_mtime;
		dbug_print("ioctl", ("   ctime %x %x",
			ret.pb_ctime.tv_sec, ret.pb_ctime.tv_nsec));
		dbug_print("ioctl", ("   mtime %x %x",
			ret.pb_mtime.tv_sec, ret.pb_mtime.tv_nsec));
	}
	return (error);
}


// -----------------------------------------------------------------
//
//			cfsd_kmod::kmod_rename
//
// Description:
// Arguments:
//	olddir
//	oldname
//	newdir
//	newname
//	credp
// Returns:
//	Returns ...
// Preconditions:
//	precond(olddir)
//	precond(oldname)
//	precond(newdir)
//	precond(newname)
//	precond(credp)

int
cfsd_kmod::kmod_rename(cfs_fid_t *olddir, const char *oldname, cfs_fid_t *newdir,
    const char *newname, const cfs_cid_t *cidp, cred_t *credp,
    cfs_timestruc_t *ctimep, cfs_timestruc_t *delctimep, const cfs_cid_t *delcidp)
{
	dbug_enter("cfsd_kmod::kmod_rename");

	dbug_precond(olddir);
	dbug_precond(oldname);
	dbug_precond(newdir);
	dbug_precond(newname);
	dbug_precond(credp);
	dbug_precond(ctimep);

	cachefsio_rename_arg_t info;
	info.rn_olddir = *olddir;
	dbug_assert(strlen(oldname) < MAXNAMELEN);
	strcpy(info.rn_oldname, oldname);
	info.rn_newdir = *newdir;
	dbug_assert(strlen(newname) < MAXNAMELEN);
	strcpy(info.rn_newname, newname);
	info.rn_cid = *cidp;
	int len = sizeof (cred_t) + ((credp->cr_ngroups - 1) * sizeof (gid_t));
	memcpy(&info.rn_cred, credp, len);
	info.rn_del_getctime = delctimep ? 1 : 0;
	info.rn_del_cid = *delcidp;

	cachefsio_rename_return_t ret;
	int error = 0;
	int xx;
	xx = i_doioctl(CFSDCMD_RENAME, &info, sizeof (info),
	    &ret, sizeof (ret));
	if (xx)
		error = errno;

	dbug_print("ioctl", ("returns %d, error %d", xx, error));
	i_format_fid(olddir);
	dbug_print("ioctl", ("   old dir fid \"%s\"", i_fidbuf));
	i_format_fid(newdir);
	dbug_print("ioctl", ("   new dir fid \"%s\"", i_fidbuf));
	dbug_print("ioctl", ("   old name '%s'  new name '%s'",
		oldname, newname));
	i_print_cred(credp);
	if (xx == 0) {
		*ctimep = ret.rn_ctime;
		dbug_print("ioctl", ("   ctime %x %x",
		    ctimep->tv_sec, ctimep->tv_nsec));
		if (delctimep) {
			*delctimep = ret.rn_del_ctime;
			dbug_print("ioctl", ("   del ctime %x %x",
			    delctimep->tv_sec, delctimep->tv_nsec));
		}
	}
	return (error);
}

// -----------------------------------------------------------------
//
//			cfsd_kmod::kmod_setattr
//
// Description:
// Arguments:
//	fidp
//	vattrp
//	flags
//	credp
// Returns:
//	Returns ...
// Preconditions:
//	precond(fidp)
//	precond(vattrp)
//	precond(credp)

int
cfsd_kmod::kmod_setattr(cfs_fid_t *fidp, const cfs_cid_t *cidp,
    cfs_vattr_t *vattrp, int flags,
    cred_t *credp, cfs_timestruc_t *ctimep, cfs_timestruc_t *mtimep)
{
	dbug_enter("cfsd_kmod::kmod_setattr");

	dbug_precond(fidp);
	dbug_precond(vattrp);
	dbug_precond(credp);

	cachefsio_setattr_arg_t info;
	info.sa_backfid = *fidp;
	info.sa_cid = *cidp;
	info.sa_vattr = *vattrp;
	info.sa_flags = flags;
	int len = sizeof (cred_t) + ((credp->cr_ngroups - 1) * sizeof (gid_t));
	memcpy(&info.sa_cred, credp, len);

	cachefsio_setattr_return_t ret;
	int error = 0;
	int xx;
	xx = i_doioctl(CFSDCMD_SETATTR, &info, sizeof (info),
	    &ret, sizeof (ret));
	if (xx)
		error = errno;

	dbug_print("ioctl", ("returns %d, error %d", xx, error));
	dbug_print("ioctl", ("   flags 0x%x", flags));
	i_format_fid(fidp);
	dbug_print("ioctl", ("   fid \"%s\"", i_fidbuf));
	i_print_attr(vattrp);
	i_print_cred(credp);
	if (xx == 0) {
		*ctimep = ret.sa_ctime;
		*mtimep = ret.sa_mtime;
		dbug_print("ioctl", ("   ctime %x %x",
			ctimep->tv_sec, ctimep->tv_nsec));
		dbug_print("ioctl", ("   mtime %x %x",
			mtimep->tv_sec, mtimep->tv_nsec));
	}
	return (error);
}

// -----------------------------------------------------------------
//
//			cfsd_kmod::kmod_setsecattr
//
// Description:
// Arguments:
//	fidp
//	aclcnt
//	dfaclcnt
//	acl
//	flags
//	credp
// Returns:
//	Returns ...
// Preconditions:
//	precond(fidp)
//	precond(acl)
//	precond(credp)
//	precond(aclcnt + dfaclcnt <= MAX_ACL_ENTRIES)
int cfsd_kmod::kmod_setsecattr(cfs_fid_t *fidp, const cfs_cid_t *cidp,
    u_long mask, int aclcnt, int dfaclcnt, const aclent_t *acl,
    cred_t *credp, cfs_timestruc_t *ctimep, cfs_timestruc_t *mtimep)
{
	dbug_enter("cfsd_kmod::kmod_setsecattr");

	dbug_precond(fidp);
	dbug_precond(acl);
	dbug_precond(credp);
	dbug_precond(aclcnt + dfaclcnt <= MAX_ACL_ENTRIES);

	cachefsio_setsecattr_arg_t info;
	info.sc_backfid = *fidp;
	info.sc_cid = *cidp;
	info.sc_mask = mask;
	info.sc_aclcnt = aclcnt;
	info.sc_dfaclcnt = dfaclcnt;
	memcpy(&info.sc_acl, acl, (aclcnt + dfaclcnt) * sizeof (aclent_t));
	int len = sizeof (cred_t) + ((credp->cr_ngroups - 1) * sizeof (gid_t));
	memcpy(&info.sc_cred, credp, len);

	cachefsio_setsecattr_return_t ret;
	int error = 0;
	int xx;
	xx = i_doioctl(CFSDCMD_SETSECATTR, &info, sizeof (info),
	    &ret, sizeof (ret));
	if (xx)
		error = errno;

	dbug_print("ioctl", ("returns %d, error %d", xx, error));
	i_format_fid(fidp);
	dbug_print("ioctl", ("   fid \"%s\"", i_fidbuf));
	dbug_print("ioctl", ("   aclcnt %d dfaclcnt %d", aclcnt, dfaclcnt));
	i_print_cred(credp);
	if (xx == 0) {
		*ctimep = ret.sc_ctime;
		*mtimep = ret.sc_mtime;
		dbug_print("ioctl", ("   ctime %x %x",
			ctimep->tv_sec, ctimep->tv_nsec));
		dbug_print("ioctl", ("   mtime %x %x",
			mtimep->tv_sec, mtimep->tv_nsec));
	}
	return (error);
}

// -----------------------------------------------------------------
//
//			cfsd_kmod::kmod_remove
//
// Description:
// Arguments:
//	fidp
//	namep
//	credp
//	ctimep
// Returns:
//	Returns ...
// Preconditions:
//	precond(fidp)
//	precond(namep)
//	precond(credp)

int
cfsd_kmod::kmod_remove(const cfs_fid_t *fidp, const cfs_cid_t *cidp,
    const char *namep, const cred_t *credp, cfs_timestruc_t *ctimep)
{
	dbug_enter("cfsd_kmod::kmod_remove");

	dbug_precond(fidp);
	dbug_precond(namep);
	dbug_precond(credp);

	cachefsio_remove_t info;
	info.rm_fid = *fidp;
	info.rm_cid = *cidp;
	dbug_assert(strlen(namep) < MAXNAMELEN);
	strcpy(info.rm_name, namep);
	int len = sizeof (cred_t) + ((credp->cr_ngroups - 1) * sizeof (gid_t));
	memcpy(&info.rm_cred, credp, len);
	info.rm_getctime = ctimep ? 1 : 0;

	if (ctimep)
		len = sizeof (*ctimep);
	else
		len = 0;

	int error = 0;
	int xx;
	xx = i_doioctl(CFSDCMD_REMOVE, &info, sizeof (info), ctimep, len);
	if (xx)
		error = errno;

	dbug_print("ioctl", ("returns %d, error %d", xx, error));
	i_format_fid(fidp);
	dbug_print("ioctl", ("   fid '%s'", i_fidbuf));
	dbug_print("ioctl", ("   name '%s'", namep));
	i_print_cred(credp);
	if ((xx == 0) && ctimep) {
		dbug_print("ioctl", ("   ctime %x %x",
			ctimep->tv_sec, ctimep->tv_nsec));
	}
	return (error);
}

// -----------------------------------------------------------------
//
//			cfsd_kmod::kmod_link
//
// Description:
// Arguments:
//	dirfidp
//	namep
//	filefidp
//	credp
//	ctimep
// Returns:
//	Returns ...
// Preconditions:
//	precond(dirfidp)
//	precond(namep)
//	precond(filefidp)
//	precond(credp)

int
cfsd_kmod::kmod_link(const cfs_fid_t *dirfidp, const char *namep,
    const cfs_fid_t *filefidp, const cfs_cid_t *cidp, const cred_t *credp,
    cfs_timestruc_t *ctimep)
{
	dbug_enter("cfsd_kmod::kmod_link");

	dbug_precond(dirfidp);
	dbug_precond(namep);
	dbug_precond(filefidp);
	dbug_precond(credp);

	cachefsio_link_t info;
	info.ln_dirfid = *dirfidp;
	dbug_assert((strlen(namep) + 1) < MAXNAMELEN);
	strcpy(info.ln_name, namep);
	info.ln_filefid = *filefidp;
	info.ln_cid = *cidp;
	int len = sizeof (cred_t) + ((credp->cr_ngroups - 1) * sizeof (gid_t));
	memcpy(&info.ln_cred, credp, len);

	int error = 0;
	int xx;
	xx = i_doioctl(CFSDCMD_LINK, &info, sizeof (info),
	    ctimep, sizeof (*ctimep));
	if (xx)
		error = errno;

	dbug_print("ioctl", ("returns %d, error %d", xx, error));
	i_format_fid(dirfidp);
	dbug_print("ioctl", ("   dir fid '%s'", i_fidbuf));
	dbug_print("ioctl", ("   name '%s'", namep));
	i_format_fid(filefidp);
	dbug_print("ioctl", ("   file fid '%s'", i_fidbuf));
	i_print_cred(credp);
	if (xx == 0) {
		dbug_print("ioctl", ("   ctime %x %x",
			ctimep->tv_sec, ctimep->tv_nsec));
	}
	return (error);
}

// -----------------------------------------------------------------
//
//			cfsd_kmod::kmod_mkdir
//
// Description:
// Arguments:
//	dirfidp
//	namep
//	vattrp
//	credp
//	newfidp
// Returns:
//	Returns ...
// Preconditions:
//	precond(dirfidp)
//	precond(namep)
//	precond(vattrp)
//	precond(credp)
//	precond(newfidp)

int
cfsd_kmod::kmod_mkdir(const cfs_fid_t *dirfidp, const char *namep,
    const cfs_cid_t *cidp,
    const cfs_vattr_t *vattrp, const cred_t *credp, cfs_fid_t *newfidp)
{
	dbug_enter("cfsd_kmod::kmod_mkdir");

	dbug_precond(dirfidp);
	dbug_precond(namep);
	dbug_precond(vattrp);
	dbug_precond(credp);
	dbug_precond(newfidp);

	cachefsio_mkdir_t info;
	info.md_dirfid = *dirfidp;
	dbug_assert((strlen(namep) + 1) < MAXNAMELEN);
	strcpy(info.md_name, namep);
	info.md_cid = *cidp;
	info.md_vattr = *vattrp;
	int len = sizeof (cred_t) + ((credp->cr_ngroups - 1) * sizeof (gid_t));
	memcpy(&info.md_cred, credp, len);

	int error = 0;
	int xx;
	xx = i_doioctl(CFSDCMD_MKDIR, &info, sizeof (info),
	    newfidp, sizeof (*newfidp));
	if (xx)
		error = errno;

	dbug_print("ioctl", ("returns %d, error %d", xx, error));
	i_format_fid(dirfidp);
	dbug_print("ioctl", ("   dir fid '%s'", i_fidbuf));
	dbug_print("ioctl", ("   name '%s'", namep));
	i_print_attr(vattrp);
	i_print_cred(credp);
	if (xx == 0) {
		i_format_fid(newfidp);
		dbug_print("ioctl", ("   file fid '%s'", i_fidbuf));
	}
	return (error);
}

// -----------------------------------------------------------------
//
//			cfsd_kmod::kmod_rmdir
//
// Description:
// Arguments:
//	dirfidp
//	namep
//	credp
// Returns:
//	Returns ...
// Preconditions:
//	precond(dirfidp)
//	precond(namep)
//	precond(credp)

int
cfsd_kmod::kmod_rmdir(const cfs_fid_t *dirfidp, const char *namep,
    const cred_t *credp)
{
	dbug_enter("cfsd_kmod::kmod_rmdir");

	dbug_precond(dirfidp);
	dbug_precond(namep);
	dbug_precond(credp);

	cachefsio_rmdir_t info;
	info.rd_dirfid = *dirfidp;
	dbug_assert((strlen(namep) + 1) < MAXNAMELEN);
	strcpy(info.rd_name, namep);
	int len = sizeof (cred_t) + ((credp->cr_ngroups - 1) * sizeof (gid_t));
	memcpy(&info.rd_cred, credp, len);

	int error = 0;
	int xx;
	xx = i_doioctl(CFSDCMD_RMDIR, &info, sizeof (info), NULL, 0);
	if (xx)
		error = errno;

	dbug_print("ioctl", ("returns %d, error %d", xx, error));
	i_format_fid(dirfidp);
	dbug_print("ioctl", ("   dir fid '%s'", i_fidbuf));
	dbug_print("ioctl", ("   name '%s'", namep));
	i_print_cred(credp);
	return (error);
}

// -----------------------------------------------------------------
//
//			cfsd_kmod::kmod_symlink
//
// Description:
// Arguments:
//	dirfidp
//	namep
//	linkvalp
//	vattrp
//	credp
//	ctimep
//	mtimep
// Returns:
//	Returns ...
// Preconditions:
//	precond(dirfidp)
//	precond(namep)
//	precond(linkvalp)
//	precond(vattrp)
//	precond(credp)
//	precond(ctimep)
//	precond(mtimep)

int
cfsd_kmod::kmod_symlink(const cfs_fid_t *dirfidp, const char *namep,
    const cfs_cid_t *cidp,
    const char *linkvalp, const cfs_vattr_t *vattrp,
    const cred_t *credp,
    cfs_fid_t *newfidp, cfs_timestruc_t *ctimep, cfs_timestruc_t *mtimep)
{
	dbug_enter("cfsd_kmod::kmod_symlink");

	dbug_precond(dirfidp);
	dbug_precond(namep);
	dbug_precond(linkvalp);
	dbug_precond(vattrp);
	dbug_precond(credp);
	dbug_precond(ctimep);
	dbug_precond(mtimep);

	cachefsio_symlink_arg_t info;
	info.sy_dirfid = *dirfidp;
	dbug_assert(strlen(namep) < MAXNAMELEN);
	strcpy(info.sy_name, namep);
	dbug_assert(strlen(linkvalp) < MAXPATHLEN);
	info.sy_cid = *cidp;
	strcpy(info.sy_link, linkvalp);
	info.sy_vattr = *vattrp;
	int len = sizeof (cred_t) + ((credp->cr_ngroups - 1) * sizeof (gid_t));
	memcpy(&info.sy_cred, credp, len);

	cachefsio_symlink_return_t ret;
	int error = 0;
	int xx;
	xx = i_doioctl(CFSDCMD_SYMLINK, &info, sizeof (info),
	    &ret, sizeof (ret));
	if (xx)
		error = errno;

	dbug_print("ioctl", ("returns %d, error %d", xx, error));
	i_format_fid(dirfidp);
	dbug_print("ioctl", ("   dir fid '%s'", i_fidbuf));
	dbug_print("ioctl", ("   name '%s'", namep));
	dbug_print("ioctl", ("   link '%s'", linkvalp));
	i_print_attr(vattrp);
	i_print_cred(credp);
	if (xx == 0) {
		*ctimep = ret.sy_ctime;
		*mtimep = ret.sy_mtime;
		*newfidp = ret.sy_newfid;
		dbug_print("ioctl", ("   ctime %x %x",
			ctimep->tv_sec, ctimep->tv_nsec));
		dbug_print("ioctl", ("   mtime %x %x",
			mtimep->tv_sec, mtimep->tv_nsec));
		i_format_fid(newfidp);
		dbug_print("ioctl", ("   child fid '%s'", i_fidbuf));
	}
	return (error);
}

// -----------------------------------------------------------------
//
//			cfsd_kmod::i_format_fid
//
// Description:
// Arguments:
//	fidp
// Returns:
// Preconditions:
//	precond(fidp)

void
cfsd_kmod::i_format_fid(const cfs_fid_t *fidp)
{
	ulong_t val;
	int index;
	char format[10];
	i_fidbuf[0] = '\0';

	for (index = 0; index < fidp->fid_len; index += sizeof (ulong_t)) {
		memcpy(&val, &fidp->fid_data[index], sizeof (ulong_t));
		sprintf(format, "%08x ", val);
		strcat(i_fidbuf, format);
	}
}

// -----------------------------------------------------------------
//
//			cfsd_kmod::i_print_cred
//
// Description:
// Arguments:
//	credp
// Returns:
// Preconditions:
//	precond(credp)

void
cfsd_kmod::i_print_cred(const cred_t *credp)
{
	dbug_enter("cfsd_kmod::i_print_cred");
	dbug_precond(credp);

	dbug_print("ioctl", ("credentials"));
	dbug_print("ioctl", ("  uid %d, gid %d, ref %d",
			    credp->cr_uid, credp->cr_gid, credp->cr_ref));
	dbug_print("ioctl", ("  ruid %d, rgid %d, suid %d, sgid %d",
			    credp->cr_ruid, credp->cr_rgid,
			    credp->cr_suid, credp->cr_sgid));

	char buf[100];
	buf[0] = '\0';
	char format[10];
	int xx;
	for (xx = 0; xx < credp->cr_ngroups; xx++) {
		sprintf(format, " %d", credp->cr_groups[xx]);
		strcat(buf, format);
	}
	dbug_print("ioctl", ("  ngroups %d,  %s", credp->cr_ngroups, buf));
}

// -----------------------------------------------------------------
//
//			cfsd_kmod::i_print_attr
//
// Description:
// Arguments:
//	vattrp
// Returns:
// Preconditions:
//	precond(vattrp)

void
cfsd_kmod::i_print_attr(const cfs_vattr_t *vp)
{
	dbug_enter("cfsd_kmod::i_print_attr");
	dbug_precond(vp);

	dbug_print("ioctl", ("attributes"));
	dbug_print("ioctl", ("  mask 0x%x", vp->va_mask));
	if (vp->va_mask & AT_TYPE)
		dbug_print("ioctl", ("  type %d", vp->va_type));
	if (vp->va_mask & AT_MODE)
		dbug_print("ioctl", ("  mode 0%o", vp->va_mode));
	if (vp->va_mask & AT_UID)
		dbug_print("ioctl", ("  uid %d", vp->va_uid));
	if (vp->va_mask & AT_GID)
		dbug_print("ioctl", ("  gid %d", vp->va_gid));
	if (vp->va_mask & AT_FSID)
		dbug_print("ioctl", ("  fsid %08x", vp->va_fsid));
	if (vp->va_mask & AT_NODEID)
		dbug_print("ioctl", ("  nodeid %08x", vp->va_nodeid));
	if (vp->va_mask & AT_NLINK)
		dbug_print("ioctl", ("  nlink %d", vp->va_nlink));
	if (vp->va_mask & AT_SIZE)
		dbug_print("ioctl", ("  size %d", vp->va_size));
	if (vp->va_mask & AT_ATIME)
		dbug_print("ioctl", ("  atime %08x %08x",
				    vp->va_atime.tv_sec, vp->va_atime.tv_nsec));
	if (vp->va_mask & AT_MTIME)
		dbug_print("ioctl", ("  mtime %08x %08x",
				    vp->va_mtime.tv_sec, vp->va_mtime.tv_nsec));
	if (vp->va_mask & AT_CTIME)
		dbug_print("ioctl", ("  ctime %08x %08x",
				    vp->va_ctime.tv_sec, vp->va_ctime.tv_nsec));
	if (vp->va_mask & AT_RDEV)
		dbug_print("ioctl", ("  rdev %08x", vp->va_rdev));
	if (vp->va_mask & AT_BLKSIZE)
		dbug_print("ioctl", ("  blksize %08x", vp->va_blksize));
	if (vp->va_mask & AT_NBLOCKS)
		dbug_print("ioctl", ("  nblocks %d", vp->va_nblocks));
	if (vp->va_mask & AT_SEQ)
		dbug_print("ioctl", ("  seq %d", vp->va_seq));
}

//
//			cfsd_kmod::i_doioctl
//
// Description:
//	Helper routine for others in this file.  Just packages up
//	arguments and does the ioctl operation.
// Arguments:
//	cmd
//	sdata
//	slen
//	rdata
//	rlen
// Returns:
//	Returns the result of the ioctl operation.
// Preconditions:

int
cfsd_kmod::i_doioctl(enum cfsdcmd_cmds cmd, void *sdata, int slen,
    void *rdata, int rlen)
{
	cachefsio_dcmd dcmd;
	dcmd.d_cmd = cmd;
	dcmd.d_sdata = sdata;
	dcmd.d_slen = slen;
	dcmd.d_rdata = rdata;
	dcmd.d_rlen = rlen;
	int xx = ioctl(i_fd, CACHEFSIO_DCMD, &dcmd);
	return (xx);
}
