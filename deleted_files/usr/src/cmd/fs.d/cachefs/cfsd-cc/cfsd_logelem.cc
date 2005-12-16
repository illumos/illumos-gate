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
//			cfsd_logelem.cc
//
// Methods of the cfsd_logelem* classes.

#pragma ident	"%Z%%M%	%I%	%E% SMI"
// Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
// Use is subject to license terms.

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <synch.h>
#include <unistd.h>
#include <stdarg.h>
#include <string.h>
#include <libintl.h>
#include <errno.h>
#include <sys/utsname.h>
#include <sys/vfs.h>
#include <sys/cred.h>
#include <sys/attr.h>
#include <sys/param.h>
#include <sys/types.h>
#include <rw/tphdict.h>
#include <rw/cstring.h>
#include <rw/regexp.h>
#include <rw/rstream.h>
#include <rw/tpdlist.h>
#include <sys/fs/cachefs_fs.h>
#include <sys/fs/cachefs_dlog.h>
#include <sys/fs/cachefs_ioctl.h>
#include <mdbug-cc/mdbug.h>

#include "cfsd_maptbl.h"
#include "cfsd_logfile.h"
#include "cfsd_kmod.h"
#include "cfsd_logelem.h"

#define	dl_ctime dl_times.tm_ctime
#define	dl_mtime dl_times.tm_mtime
#define	TIMECHANGE(A, B) (memcmp(&A, &B, sizeof (A)) != 0)
#define	X_OPTIMIZED -2
#define	X_CONFLICT -3

#define TIMEDOUT(XX) ((XX == ETIMEDOUT) || (XX == EIO))


// -----------------------------------------------------------------
//
//			cfsd_logelem::cfsd_logelem
//
// Description:
//	Constructor for the cfsd_logelem abstract base class.
// Arguments:
// Returns:
// Preconditions:

cfsd_logelem::cfsd_logelem(cfsd_maptbl *tblp, cfsd_logfile *lfp,
    cfsd_kmod *kmodp)
{
	dbug_enter("cfsd_logelem::cfsd_logelem");

	i_tblp = tblp;
	i_lfp = lfp;
	i_kmodp = kmodp;

	i_entp = lfp->logfile_entry();
	i_offset = lfp->logfile_entry_off();
	dbug_assert(i_entp);
	i_messagep = NULL;
}

// -----------------------------------------------------------------
//
//			cfsd_logelem::~cfsd_logelem
//
// Description:
//	Destructor for the cfsd_logelem abstract base class.
// Arguments:
// Returns:
// Preconditions:


cfsd_logelem::~cfsd_logelem()
{
	dbug_enter("cfsd_logelem::~cfsd_logelem");
	delete i_messagep;
}

// -----------------------------------------------------------------
//
//			cfsd_logelem::logelem_message
//
// Description:
// Arguments:
// Returns:
//	Returns the string describing the message or NULL if
//	there is no message.
// Preconditions:

const char *
cfsd_logelem::logelem_message()
{
	dbug_enter("cfsd_logelem::logelem_message");

	if (i_messagep) {
		return (i_messagep->data());
	} else {
		return (NULL);
	}
}

// -----------------------------------------------------------------
//
//			cfsd_logelem::i_print_cred
//
// Description:
// Arguments:
//	credp
// Returns:
// Preconditions:
//	precond(credp)

void
cfsd_logelem::i_print_cred(cred_t *credp)
{
	dbug_enter("cfsd_logelem::i_print_cred");
	dbug_precond(credp);

	dbug_print("dump", ("credentials"));
	dbug_print("dump", ("  uid %d, gid %d, ref %d",
			    credp->cr_uid, credp->cr_gid, credp->cr_ref));
	dbug_print("dump", ("  ruid %d, rgid %d, suid %d, sgid %d",
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
	dbug_print("dump", ("  ngroups %d,  %s", credp->cr_ngroups, buf));
}

// -----------------------------------------------------------------
//
//			cfsd_logelem::i_print_attr
//
// Description:
// Arguments:
//	vattrp
// Returns:
// Preconditions:
//	precond(vattrp)

void
cfsd_logelem::i_print_attr(cfs_vattr_t *vp)
{
	dbug_enter("cfsd_logelem::i_print_attr");
	dbug_precond(vp);

	dbug_print("dump", ("attributes"));
	dbug_print("dump", ("  mask 0x%x", vp->va_mask));
	if (vp->va_mask & AT_TYPE)
		dbug_print("dump", ("  type %d", vp->va_type));
	if (vp->va_mask & AT_MODE)
		dbug_print("dump", ("  mode 0%o", vp->va_mode));
	if (vp->va_mask & AT_UID)
		dbug_print("dump", ("  uid %d", vp->va_uid));
	if (vp->va_mask & AT_GID)
		dbug_print("dump", ("  gid %d", vp->va_gid));
	if (vp->va_mask & AT_FSID)
		dbug_print("dump", ("  fsid %08x", vp->va_fsid));
	if (vp->va_mask & AT_NODEID)
		dbug_print("dump", ("  nodeid %08x", vp->va_nodeid));
	if (vp->va_mask & AT_NLINK)
		dbug_print("dump", ("  nlink %d", vp->va_nlink));
	if (vp->va_mask & AT_SIZE)
		dbug_print("dump", ("  size %d", vp->va_size));
	if (vp->va_mask & AT_ATIME)
		dbug_print("dump", ("  atime %08x %08x",
				    vp->va_atime.tv_sec, vp->va_atime.tv_nsec));
	if (vp->va_mask & AT_MTIME)
		dbug_print("dump", ("  mtime %08x %08x",
				    vp->va_mtime.tv_sec, vp->va_mtime.tv_nsec));
	if (vp->va_mask & AT_CTIME)
		dbug_print("dump", ("  ctime %08x %08x",
				    vp->va_ctime.tv_sec, vp->va_ctime.tv_nsec));
	if (vp->va_mask & AT_RDEV)
		dbug_print("dump", ("  rdev %08x", vp->va_rdev));
	if (vp->va_mask & AT_BLKSIZE)
		dbug_print("dump", ("  blksize %08x", vp->va_blksize));
	if (vp->va_mask & AT_NBLOCKS)
		dbug_print("dump", ("  nblocks %d", vp->va_nblocks));
	if (vp->va_mask & AT_SEQ)
		dbug_print("dump", ("  seq %d", vp->va_seq));
}

// -----------------------------------------------------------------
//
//			cfsd_logelem::i_format_fid
//
// Description:
// Arguments:
//	fidp
// Returns:
// Preconditions:
//	precond(fidp)

void
cfsd_logelem::i_format_fid(cfs_fid_t *fidp)
{
	u_int val;
	int index;
	char format[10];
	i_fidbuf[0] = '\0';

	for (index = 0; index < fidp->fid_len; index += sizeof (u_int)) {
		memcpy(&val, &fidp->fid_data[index], sizeof (u_int));
		sprintf(format, "%08x ", val);
		strcat(i_fidbuf, format);
	}
}


// -----------------------------------------------------------------
//
//			cfsd_logelem::i_lostfound
//
// Description:
//	Called when there is a conflict on a file.
// Arguments:
//	cidp	cid of file to move to lost+found
//	pcidp	parent cid if known, else null
//	namep	name of file if known, else null
// Returns:
//	Returns 0 for success, EIO if file could not be moved.
// Preconditions:
//	precond(cidp)

int
cfsd_logelem::i_lostfound(cfs_cid_t *cidp, cfs_cid_t *pcidp, const char *namep,
    cred_t *cred)
{
	dbug_enter("cfsd_logelem::i_lostfound");
	dbug_precond(cidp);
	dbug_precond(cred);

	cfs_dlog_mapping_space map;
	int xx;
	cfs_fid_t *fp, dirfid;
	cachefsio_getinfo_t ginfo;
	char namebuf[40];

	// make an alternate name for the file
	if (namep == NULL)
		sprintf(namebuf, "fileno_%x", cidp->cid_fileno);

	// get info about the file from the cache
	xx = i_kmodp->kmod_getinfo(cidp, &ginfo);
	if (xx) {
		if (namep == NULL) {
			namep = namebuf;
		}
		i_resolution(gettext("Operation on '"), namep,
		    gettext("' skipped."), NULL);
		return (0);
	}

	// determine what we want to call this file
	if (namep == NULL) {
		if (ginfo.gi_name[0] == '\0')
			namep = namebuf;
		else
			namep = ginfo.gi_name;
	}

	// if not a regular file or not modified
	if ((ginfo.gi_attr.va_type != VREG) || !ginfo.gi_modified) {
		i_resolution(gettext("Operation on '"), namep,
		    gettext("' skipped."), NULL);
		return (0);
	}

	// get the fid of the parent directory from the passed in cid
	int gotdirfid = 0;
	if (pcidp) {
		// see if we have a valid mapping for the parent cid
		xx = i_tblp->maptbl_get(*pcidp, &map);
		if (xx == -1)
			return (EIO);
		if ((xx == 0) && (0 < map.ms_fid)) {
			xx = i_lfp->logfile_offset(map.ms_fid, (caddr_t *)&fp);
			if (xx)
				return (EIO);
			if (fp->fid_len) {
				gotdirfid = 1;
				dirfid = *fp;
			}
		}

		// otherwise try to get the fid from the cache
		if (gotdirfid == 0) {
			xx = i_kmodp->kmod_cidtofid(pcidp, &dirfid);
			if (xx == 0)
				gotdirfid = 1;
		}
	}

	// if not parent fid yet, try to get one from the dir in the cache
	if ((gotdirfid == 0) && ginfo.gi_pcid.cid_fileno) {
		// see if we have a valid mapping for the cache parent cid
		xx = i_tblp->maptbl_get(ginfo.gi_pcid, &map);
		if (xx == -1)
			return (EIO);
		if ((xx == 0) && (0 < map.ms_fid)) {
			xx = i_lfp->logfile_offset(map.ms_fid, (caddr_t *)&fp);
			if (xx)
				return (EIO);
			if (fp->fid_len) {
				gotdirfid = 1;
				dirfid = *fp;
			}
		}

		// otherwise try to get the fid from the cache
		if (gotdirfid == 0) {
			xx = i_kmodp->kmod_cidtofid(&ginfo.gi_pcid, &dirfid);
			if (xx == 0)
				gotdirfid = 1;
		}
	}

	int wrotefile = 0;

	// if we found a parent directory
	if (gotdirfid) {
		// get the host name
		char *machnamep;
		struct utsname info;
		int xx = uname(&info);
		if (xx == -1)
			machnamep = "client";
		else
			machnamep = info.nodename;

		// find a name we can call this file
		char *np;
		char namebuf2[MAXNAMELEN * 2];
		int foundname = 0;
		int index;
#define		MAXTRIES 10
		for (index = 0; index < MAXTRIES; index++) {
			// construct the name
			sprintf(namebuf2, "%s.conflict.%s.%x", namep,
			    machnamep, index);
			int len = strlen(namebuf2) + 1;
			if (len > MAXNAMELEN)
				np = &namebuf2[len - MAXNAMELEN];
			else
				np = namebuf2;

			// see if it exists
			xx = i_kmodp->kmod_getattrname(&dirfid, np, cred,
			    NULL, NULL);

			// timeout error, pass the error back up
			if (TIMEDOUT(xx))
				return (ETIMEDOUT);

			// file does not exist, so try to use it
			if (xx == ENOENT) {
				foundname = 1;
				break;
			}

			// any other error on the directory, give up
			if (xx)
				break;
		}

		// if we found a name
		cfs_fid_t filefid;
		if (foundname) {
			// set up attributes for the file
			struct cfs_vattr vattr;
			vattr.va_type = VREG;
			vattr.va_mode = ginfo.gi_attr.va_mode;
			vattr.va_mask = AT_TYPE | AT_MODE | AT_SIZE;
			vattr.va_size = 0;

			// create the file
			xx = i_kmodp->kmod_create(&dirfid, np, NULL, &vattr,
			    NONEXCL, VWRITE, cred, &filefid, NULL, NULL);
			if (xx == 0) {
				// write the file
				xx = i_kmodp->kmod_pushback(cidp, &filefid,
				    cred, NULL, NULL, 0);
				if (xx == 0) {
					wrotefile = 1;
					i_resolution(gettext("File '"), namep,
					    gettext("' renamed as '"),
					    np, gettext("' on server."), NULL);
				}
			}
		}

	}

	// if we could not write the file to the server, move to lost+found
	if (wrotefile == 0) {
		char newname[MAXNAMELEN];

		// move the file to lost+found
		xx = i_kmodp->kmod_lostfound(cidp, namep, newname);
		if (xx == EINVAL) {
			dbug_assert(0);
			i_resolution(gettext("Operation on '"), namep,
			    gettext("' skipped."), NULL);
			return (0);
		} else if (xx) {
			i_resolution(gettext("Cannot move '"), namep,
			    gettext("' to lost+found.  "
			    "Run cachefs fsck on the file system."), NULL);
			xx = EIO;
		} else {
			i_resolution(gettext("Moved '"), namep,
			    gettext("' to " CACHEFS_LOSTFOUND_NAME "/"),
			    newname, NULL);
		}
	}

	// set the mapping to indicate conflict
	map.ms_cid = *cidp;
	map.ms_fid = X_CONFLICT;
	map.ms_times = 0;
	xx = i_tblp->maptbl_set(&map, 1);
	if (xx)
		return (EIO);

	return (xx);
}

// -----------------------------------------------------------------
//
//			cfsd_logelem::i_problem
//
// Description:
//	Specifies the problem string.
//	Pass a variable number of strings.
//	They are concatinated together to form the message.
//	Terminate the argument list with NULL.
// Arguments:
//	strp
// Returns:
// Preconditions:
//	precond(strp)

void
cfsd_logelem::i_problem(const char *strp, ...)
{
	dbug_enter("cfsd_logelem::i_problem");
	dbug_precond(strp);

	va_list ap;
	va_start(ap, strp);
	i_message("cachefsd: Problem: ", strp, ap);
	va_end(ap);
}

// -----------------------------------------------------------------
//
//			cfsd_logelem::i_resolution
//
// Description:
//	Specifies the resolution string.
//	Pass a variable number of strings.
//	They are concatinated together to form the message.
//	Terminate the argument list with NULL.
// Arguments:
//	strp
// Returns:
// Preconditions:
//	precond(strp)

void
cfsd_logelem::i_resolution(const char *strp, ...)
{
	dbug_enter("cfsd_logelem::i_resolution");
	dbug_precond(strp);

	va_list ap;
	va_start(ap, strp);
	i_message("cachefsd: Resolution: ", strp, ap);
	va_end(ap);
}

// -----------------------------------------------------------------
//
//			cfsd_logelem::i_message
//
// Description:
// Arguments:
//	prefix
//	strp
// Returns:
// Preconditions:
//	precond(prefix)
//	precond(strp)

void
cfsd_logelem::i_message(const char *prefix, const char *strp, va_list ap)
{
	dbug_enter("cfsd_logelem::i_message");

	dbug_precond(prefix);
	dbug_precond(strp);

	char *fp;

	if (i_messagep == NULL)
		i_messagep = new RWCString(prefix);
	else
		i_messagep->append(prefix);
	i_messagep->append(strp);

	for (;;) {
		fp = va_arg(ap, char *);
		if (fp == NULL)
			break;
		i_messagep->append(fp);
	}

	i_messagep->append("\n");
}

//
//			cfsd_logelem_setattr::cfsd_logelem_setattr
//
// Description:
// Arguments:
// Returns:
// Preconditions:

cfsd_logelem_setattr::cfsd_logelem_setattr(cfsd_maptbl *tblp,
    cfsd_logfile *lfp, cfsd_kmod *kmodp)
	: cfsd_logelem(tblp, lfp, kmodp)
{
	dbug_enter("cfsd_logelem_setattr::cfsd_logelem_setattr");
	i_up = &i_entp->dl_u.dl_setattr;
}

//
//			cfsd_logelem_setsecattr::cfsd_logelem_setsecattr
//
// Description:
// Arguments:
// Returns:
// Preconditions:

cfsd_logelem_setsecattr::cfsd_logelem_setsecattr(cfsd_maptbl *tblp,
    cfsd_logfile *lfp, cfsd_kmod *kmodp)
	: cfsd_logelem(tblp, lfp, kmodp)
{
	dbug_enter("cfsd_logelem_setsecattr::cfsd_logelem_setsecattr");
	i_up = &i_entp->dl_u.dl_setsecattr;
	i_acl = (const aclent_t *) ((caddr_t) i_up->dl_buffer +
	    ((i_up->dl_cred.cr_ngroups - 1) * sizeof (gid_t)));
}

//
//			cfsd_logelem_setattr::~cfsd_logelem_setattr
//
// Description:
// Arguments:
// Returns:
// Preconditions:

cfsd_logelem_setattr::~cfsd_logelem_setattr()
{
	dbug_enter("cfsd_logelem_setattr::~cfsd_logelem_setattr");
}

//
//			cfsd_logelem_setsecattr::~cfsd_logelem_setsecattr
//
// Description:
// Arguments:
// Returns:
// Preconditions:

cfsd_logelem_setsecattr::~cfsd_logelem_setsecattr()
{
	dbug_enter("cfsd_logelem_setsecattr::~cfsd_logelem_setsecattr");
}

//
//			cfsd_logelem_setattr::logelem_roll
//
// Description:
// Arguments:
// Returns:
// Preconditions:

int
cfsd_logelem_setattr::logelem_roll(u_long *)
{
	dbug_enter("cfsd_logelem_setattr::logelem_roll");

	int xx;
	cfs_fid_t filefid, *fp;
	cfs_dlog_mapping_space map;
	cfs_dlog_tm_t *tmp;
	cfs_timestruc_t ctime, mtime;
	int time_log;

	// get the mapping for this cid if it exists
	xx = i_tblp->maptbl_get(i_up->dl_cid, &map);
	if (xx == -1)
		return (EIO);

	// if a mapping was not found
	if (xx) {
		// dummy up mapping so we get values from the cache
		map.ms_cid = i_up->dl_cid;
		map.ms_fid = 0;
		map.ms_times = 0;
	}

	// done if there was a conflict on the file
	if (map.ms_fid == X_CONFLICT)
		return (0);

	// done if the file is optimized out
	if (map.ms_fid == X_OPTIMIZED)
		return (0);

	// if we have a fid in the mapping
	if (map.ms_fid) {
		// get the fid
		xx = i_lfp->logfile_offset(map.ms_fid, (caddr_t *)&fp);
		if (xx)
			return (EIO);
		filefid = *fp;
		dbug_assert(filefid.fid_len);
	}

	// else get the fid from the cache
	else {
		xx = i_kmodp->kmod_cidtofid(&i_up->dl_cid, &filefid);
		if (xx == ENOENT)
			return (0);
		if (xx) {
			i_problem(gettext("Cannot setattr."),
			    gettext(" File is no longer in the cache."),
			    NULL);
			xx = i_lostfound(&i_up->dl_cid, NULL, NULL,
			    &i_up->dl_cred);
			return (xx);
		}
	}

	// if we have timestamps in the mapping
	if (map.ms_times) {
		// get the times
		xx = i_lfp->logfile_offset(map.ms_times, (caddr_t *)&tmp);
		if (xx)
			return (EIO);
		ctime = tmp->tm_ctime;
		mtime = tmp->tm_mtime;
		time_log = 0;
	}

	// else get the timestamps from the log entry
	else {
		ctime = i_up->dl_ctime;
		mtime = i_up->dl_mtime;
		time_log = 1;
	}

	// get the attributes of the file from the back fs
	cfs_vattr_t va;
	xx = i_kmodp->kmod_getattrfid(&filefid, &i_up->dl_cred, &va);
	if (TIMEDOUT(xx))
		return (ETIMEDOUT);
	if (xx) {
		xx = i_lostfound(&i_up->dl_cid, NULL, NULL, &i_up->dl_cred);
		return (xx);
	}

	int conflict = 0;

	// conflict if mtime changed
	if (TIMECHANGE(mtime, va.va_mtime)) {
		i_problem(gettext("Cannot setattr."),
		    gettext(" File modified "),
		    time_log ?
		    gettext("while disconnected.") :
		    gettext("while rolling log."),
		    NULL);
		conflict = 1;
	}

	// conflict if ctime changed
	else if (TIMECHANGE(ctime, va.va_ctime)) {
		i_problem(gettext("Cannot setattr."),
		    gettext(" File changed "),
		    time_log ?
		    gettext("while disconnected.") :
		    gettext("while rolling log."),
		    NULL);
		conflict = 1;
	}

	// if a conflict was detected
	if (conflict) {
		xx = i_lostfound(&i_up->dl_cid, NULL, NULL, &i_up->dl_cred);
		return (xx);
	}

	// now do the setattr, get the new times
	xx = i_kmodp->kmod_setattr(&filefid, &i_up->dl_cid, &i_up->dl_attrs,
	    i_up->dl_flags, &i_up->dl_cred, &i_up->dl_ctime, &i_up->dl_mtime);
	if (TIMEDOUT(xx))
		return (ETIMEDOUT);
	if (xx) {
		i_problem(gettext("Setattr failed."),
		    gettext(" Error:"),
		    strerror(xx), NULL);
		xx = i_lostfound(&i_up->dl_cid, NULL, NULL, &i_up->dl_cred);
		return (xx);
	}

	// update the mapping to point to the new times
	map.ms_times = i_offset +
	    offsetof(cfs_dlog_entry_t, dl_u.dl_setattr.dl_times);
	xx = i_tblp->maptbl_set(&map, 1);
	if (xx)
		return (EIO);
	return (0);
}

//
//			cfsd_logelem_setattr::logelem_dump
//
// Description:
// Arguments:
// Returns:
// Preconditions:

void
cfsd_logelem_setattr::logelem_dump()
{
	dbug_enter("cfsd_logelem_setattr::logelem_dump");

	dbug_print("dump", ("SETATTR"));
	dbug_print("dump", ("len %d, valid %d, seq %d",
	    i_entp->dl_len, i_entp->dl_valid, i_entp->dl_seq));
	dbug_print("dump", ("file  cid %08x, flags 0x%x",
	    i_up->dl_cid.cid_fileno, i_up->dl_flags));
	dbug_print("dump", ("ctime %x %x, mtime %x %x",
	    i_up->dl_ctime.tv_sec, i_up->dl_ctime.tv_nsec,
	    i_up->dl_mtime.tv_sec, i_up->dl_mtime.tv_nsec));
	i_print_attr(&i_up->dl_attrs);
	i_print_cred(&i_up->dl_cred);
}

//
//			cfsd_logelem_setsecattr::logelem_roll
//
// Description:
// Arguments:
// Returns:
// Preconditions:

int
cfsd_logelem_setsecattr::logelem_roll(u_long *)
{
	dbug_enter("cfsd_logelem_setsecattr::logelem_roll");

	int xx;
	cfs_fid_t filefid, *fp;
	cfs_dlog_mapping_space map;
	cfs_dlog_tm_t *tmp;
	cfs_timestruc_t ctime, mtime;
	int time_log;

	// get the mapping for this cid if it exists
	xx = i_tblp->maptbl_get(i_up->dl_cid, &map);
	if (xx == -1)
		return (EIO);

	// if a mapping was not found
	if (xx) {
		// dummy up mapping so we get values from the cache
		map.ms_cid = i_up->dl_cid;
		map.ms_fid = 0;
		map.ms_times = 0;
	}

	// done if there was a conflict on the file
	if (map.ms_fid == X_CONFLICT)
		return (0);

	// done if the file is optimized out
	if (map.ms_fid == X_OPTIMIZED)
		return (0);

	// if we have a fid in the mapping
	if (map.ms_fid) {
		// get the fid
		xx = i_lfp->logfile_offset(map.ms_fid, (caddr_t *)&fp);
		if (xx)
			return (EIO);
		filefid = *fp;
		dbug_assert(filefid.fid_len);
	}

	// else get the fid from the cache
	else {
		xx = i_kmodp->kmod_cidtofid(&i_up->dl_cid, &filefid);
		if (xx == ENOENT)
			return (0);
		if (xx) {
			i_problem(gettext("Cannot setsecattr."),
			    gettext(" File is no longer in the cache."),
			    NULL);
			xx = i_lostfound(&i_up->dl_cid, NULL, NULL,
			    &i_up->dl_cred);
			return (xx);
		}
	}

	// if we have timestamps in the mapping
	if (map.ms_times) {
		// get the times
		xx = i_lfp->logfile_offset(map.ms_times, (caddr_t *)&tmp);
		if (xx)
			return (EIO);
		ctime = tmp->tm_ctime;
		mtime = tmp->tm_mtime;
		time_log = 0;
	}

	// else get the timestamps from the log entry
	else {
		ctime = i_up->dl_ctime;
		mtime = i_up->dl_mtime;
		time_log = 1;
	}

	// get the attributes of the file from the back fs
	cfs_vattr_t va;
	xx = i_kmodp->kmod_getattrfid(&filefid, &i_up->dl_cred, &va);
	if (TIMEDOUT(xx))
		return (ETIMEDOUT);
	if (xx) {
		xx = i_lostfound(&i_up->dl_cid, NULL, NULL, &i_up->dl_cred);
		return (xx);
	}

	int conflict = 0;

	// conflict if mtime changed
	if (TIMECHANGE(mtime, va.va_mtime)) {
		i_problem(gettext("Cannot setsecattr."),
		    gettext(" File modified "),
		    time_log ?
		    gettext("while disconnected.") :
		    gettext("while rolling log."),
		    NULL);
		conflict = 1;
	}

	// conflict if ctime changed
	else if (TIMECHANGE(ctime, va.va_ctime)) {
		i_problem(gettext("Cannot setsecattr."),
		    gettext(" File changed "),
		    time_log ?
		    gettext("while disconnected.") :
		    gettext("while rolling log."),
		    NULL);
		conflict = 1;
	}

	// if a conflict was detected
	if (conflict) {
		xx = i_lostfound(&i_up->dl_cid, NULL, NULL, &i_up->dl_cred);
		return (xx);
	}

	// now do the setsecattr, get the new times
	xx = i_kmodp->kmod_setsecattr(&filefid, &i_up->dl_cid,
	    i_up->dl_mask, i_up->dl_aclcnt, i_up->dl_dfaclcnt, i_acl,
	    &i_up->dl_cred, &i_up->dl_ctime, &i_up->dl_mtime);
	if (TIMEDOUT(xx))
		return (ETIMEDOUT);
	if (xx) {
		i_problem(gettext("Setsecattr failed."),
		    gettext(" Error:"),
		    strerror(xx), NULL);
		xx = i_lostfound(&i_up->dl_cid, NULL, NULL, &i_up->dl_cred);
		return (xx);
	}

	// update the mapping to point to the new times
	map.ms_times = i_offset +
	    offsetof(cfs_dlog_entry_t, dl_u.dl_setsecattr.dl_times);
	xx = i_tblp->maptbl_set(&map, 1);
	if (xx)
		return (EIO);
	return (0);
}

//
//			cfsd_logelem_setsecattr::logelem_dump
//
// Description:
// Arguments:
// Returns:
// Preconditions:

void
cfsd_logelem_setsecattr::logelem_dump()
{
	dbug_enter("cfsd_logelem_setsecattr::logelem_dump");

	dbug_print("dump", ("SETSECATTR"));
	dbug_print("dump", ("len %d, valid %d, seq %d",
	    i_entp->dl_len, i_entp->dl_valid, i_entp->dl_seq));
	dbug_print("dump", ("file  cid %08x",
	    i_up->dl_cid.cid_fileno));
	dbug_print("dump", ("aclcnt %d dfaclcnt %d",
	    i_up->dl_aclcnt, i_up->dl_dfaclcnt));
	dbug_print("dump", ("ctime %x %x, mtime %x %x",
	    i_up->dl_ctime.tv_sec, i_up->dl_ctime.tv_nsec,
	    i_up->dl_mtime.tv_sec, i_up->dl_mtime.tv_nsec));
	i_print_cred(&i_up->dl_cred);
}

//
//			cfsd_logelem_create::cfsd_logelem_create
//
// Description:
// Arguments:
// Returns:
// Preconditions:

cfsd_logelem_create::cfsd_logelem_create(cfsd_maptbl *tblp,
    cfsd_logfile *lfp, cfsd_kmod *kmodp)
	: cfsd_logelem(tblp, lfp, kmodp)
{
	dbug_enter("cfsd_logelem_create::cfsd_logelem_create");
	i_up = &i_entp->dl_u.dl_create;
	i_namep = i_up->dl_buffer +
		((i_up->dl_cred.cr_ngroups - 1) * sizeof (gid_t));
}

//
//			cfsd_logelem_create::~cfsd_logelem_create
//
// Description:
// Arguments:
// Returns:
// Preconditions:


cfsd_logelem_create::~cfsd_logelem_create()
{
	dbug_enter("cfsd_logelem_create::~cfsd_logelem_create");
}

//
//			cfsd_logelem_create::logelem_roll
//
// Description:
// Arguments:
// Returns:
// Preconditions:

int
cfsd_logelem_create::logelem_roll(u_long *)
{
	dbug_enter("cfsd_logelem_create::logelem_roll");

	int xx;
	cfs_fid_t filefid, *fp;
	cfs_fid_t dirfid;
	cfs_dlog_mapping_space map;
	cfs_timestruc_t ctime, mtime;

	// if the file existed at the time of this operation
	dbug_assert(i_up->dl_exists == 0);

	// see if the file no longer exists in the cache
#if 0
	xx = i_kmodp->kmod_exists(&i_up->dl_new_cid);
	if (xx) {
		dbug_assert(xx == ENOENT);

		// indicate ignore future operations on file
		map.ms_cid = i_up->dl_new_cid;
		map.ms_fid = X_OPTIMIZED;
		map.ms_times = 0;
		xx = i_tblp->maptbl_set(&map, 1);
		if (xx)
			return (EIO);
		return (0);
	}
#endif

	// get the fid of the parent directory
	xx = i_tblp->maptbl_get(i_up->dl_parent_cid, &map);
	if (xx == -1)
		return (EIO);
	if (xx || (map.ms_fid <= 0)) {
		xx = i_kmodp->kmod_cidtofid(&i_up->dl_parent_cid, &dirfid);
		if (xx) {
			i_problem(gettext("Cannot create file '"), i_namep,
			    gettext("'. Parent directory no longer exists."),
			    NULL);
			xx = i_lostfound(&i_up->dl_new_cid,
			    &i_up->dl_parent_cid, i_namep, &i_up->dl_cred);
			return (xx);
		}
	} else {
		xx = i_lfp->logfile_offset(map.ms_fid, (caddr_t *)&fp);
		if (xx)
			return (EIO);
		dirfid = *fp;
		dbug_assert(dirfid.fid_len);
	}

	// if the file exists on the back fs
	cfs_fid_t filefid2;
	cfs_vattr_t va;
	xx = i_kmodp->kmod_getattrname(&dirfid, i_namep, &i_up->dl_cred,
	    &va, &filefid2);
	if (TIMEDOUT(xx))
		return (ETIMEDOUT);

	// if the file exists on the back file system
	if (xx == 0) {
		i_problem(gettext("Cannot create file '"), i_namep,
		    gettext("'. File created while disconnected"), NULL);
		xx = i_lostfound(&i_up->dl_new_cid,
		    &i_up->dl_parent_cid, i_namep, &i_up->dl_cred);
		return (xx);
	}

	// do the create
	xx = i_kmodp->kmod_create(&dirfid, i_namep, &i_up->dl_new_cid,
	    &i_up->dl_attrs, NONEXCL, i_up->dl_mode, &i_up->dl_cred,
	    &i_up->dl_fid, &i_up->dl_ctime, &i_up->dl_mtime);
	if (xx) {
		if (TIMEDOUT(xx))
			return (ETIMEDOUT);

		// create failed move to lost and found
		i_problem(gettext("Cannot create file '"),
		    i_namep, gettext("'. Error:."),
		    strerror(xx), NULL);
		xx = i_lostfound(&i_up->dl_new_cid,
		    &i_up->dl_parent_cid, i_namep, &i_up->dl_cred);
		return (xx);
	}

	// update the mapping to point to the new fid and times
	map.ms_cid = i_up->dl_new_cid;
	map.ms_fid = i_offset +
	    offsetof(cfs_dlog_entry_t, dl_u.dl_create.dl_fid);
	map.ms_times = i_offset +
	    offsetof(cfs_dlog_entry_t, dl_u.dl_create.dl_times);
	xx = i_tblp->maptbl_set(&map, 1);
	if (xx)
		return (EIO);

	return (0);
}

//
//			cfsd_logelem_create::logelem_dump
//
// Description:
// Arguments:
// Returns:
// Preconditions:

void
cfsd_logelem_create::logelem_dump()
{
	dbug_enter("cfsd_logelem_create::logelem_dump");

	dbug_print("dump", ("CREATE"));
	dbug_print("dump", ("len %d, valid %d, seq %d",
	    i_entp->dl_len, i_entp->dl_valid, i_entp->dl_seq));
	dbug_print("dump", ("directory cid %08x",
		i_up->dl_parent_cid.cid_fileno));
	dbug_print("dump", ("file      cid %08x",
		i_up->dl_new_cid.cid_fileno));
	dbug_print("dump", ("name \"%s\"", i_namep));
	dbug_print("dump", ("exclusive %d, mode 0%o, destexists %d",
		i_up->dl_excl, i_up->dl_mode, i_up->dl_exists));
	dbug_print("dump", ("ctime %x %x, mtime %x %x",
	    i_up->dl_ctime.tv_sec, i_up->dl_ctime.tv_nsec,
	    i_up->dl_mtime.tv_sec, i_up->dl_mtime.tv_nsec));
	i_print_attr(&i_up->dl_attrs);
	i_print_cred(&i_up->dl_cred);
}

//
//			cfsd_logelem_remove::cfsd_logelem_remove
//
// Description:
// Arguments:
// Returns:
// Preconditions:


cfsd_logelem_remove::cfsd_logelem_remove(cfsd_maptbl *tblp,
    cfsd_logfile *lfp, cfsd_kmod *kmodp)
	: cfsd_logelem(tblp, lfp, kmodp)
{
	dbug_enter("cfsd_logelem_remove::cfsd_logelem_remove");
	i_up = &i_entp->dl_u.dl_remove;
	i_namep = i_up->dl_buffer +
		((i_up->dl_cred.cr_ngroups - 1) * sizeof (gid_t));
}

//
//			cfsd_logelem_remove::~cfsd_logelem_remove
//
// Description:
// Arguments:
// Returns:
// Preconditions:

cfsd_logelem_remove::~cfsd_logelem_remove()
{
	dbug_enter("cfsd_logelem_remove::~cfsd_logelem_remove");
}

// -----------------------------------------------------------------
//
//			cfsd_logelem_remove::logelem_roll
//
// Description:
// Arguments:
// Returns:
// Preconditions:

int
cfsd_logelem_remove::logelem_roll(u_long *)
{
	dbug_enter("cfsd_logelem_remove::logelem_roll");

	int xx;
	cfs_fid_t *fp;
	cfs_fid_t dirfid;
	cfs_dlog_mapping_space map, dirmap;
	cfs_timestruc_t ctime, mtime;
	int time_log;
	cfs_dlog_tm_t *tmp;

	// get the mapping for this cid if it exists
	xx = i_tblp->maptbl_get(i_up->dl_child_cid, &map);
	if (xx == -1)
		return (EIO);

	// done if there was a conflict on the file
	if (map.ms_fid == X_CONFLICT)
		return (0);

	// done if the file is optimized out
	if (map.ms_fid == X_OPTIMIZED)
		return (0);

	// if a mapping was not found
	if (xx) {
		// dummy up mapping so we get values from the cache
		map.ms_cid = i_up->dl_child_cid;
		map.ms_fid = 0;
		map.ms_times = 0;
	}

	// if we have timestamps in the mapping
	if (map.ms_times) {
		// get the times
		xx = i_lfp->logfile_offset(map.ms_times, (caddr_t *)&tmp);
		if (xx)
			return (EIO);
		ctime = tmp->tm_ctime;
		mtime = tmp->tm_mtime;
		time_log = 0;
	}

	// else get the timestamps from the log entry
	else {
		ctime = i_up->dl_ctime;
		mtime = i_up->dl_mtime;
		time_log = 1;
	}

	// get the fid of the parent directory
	xx = i_tblp->maptbl_get(i_up->dl_parent_cid, &dirmap);
	if (xx == -1)
		return (EIO);
	if (xx || (dirmap.ms_fid <= 0)) {
		xx = i_kmodp->kmod_cidtofid(&i_up->dl_parent_cid, &dirfid);
		if (xx) {
			i_problem(gettext("Cannot remove file '"), i_namep,
			    gettext("'. Parent directory no longer exists"),
			    NULL);
			i_resolution(gettext("Operation on '"), i_namep,
			    gettext("' skipped."), NULL);
			return (0);
		}
	} else {
		xx = i_lfp->logfile_offset(dirmap.ms_fid, (caddr_t *)&fp);
		if (xx)
			return (EIO);
		dirfid = *fp;
		dbug_assert(dirfid.fid_len);
	}

	// get file attributes
	cfs_fid_t filefid2;
	cfs_vattr_t va;
	xx = i_kmodp->kmod_getattrname(&dirfid, i_namep, &i_up->dl_cred,
	    &va, &filefid2);
	if (TIMEDOUT(xx))
		return (ETIMEDOUT);

	// if the file no longer exists on the back fs
	if (xx == ENOENT) {
		i_problem(gettext("Cannot remove file '"), i_namep,
		    gettext("'. File no longer exists."), NULL);
		i_resolution(gettext("Operation on '"), i_namep,
		    gettext("' skipped."), NULL);
		return (0);
	} else if (xx) {
		i_problem(gettext("Cannot remove file '"), i_namep,
		    gettext("'. Cannot get file attributes from server. "),
		    gettext("Error: "), strerror(xx),
		    NULL);
		i_resolution(gettext("Operation on '"), i_namep,
		    gettext("' skipped."), NULL);
		return (0);
	}

	// conflict if mtime changed
	if (TIMECHANGE(mtime, va.va_mtime)) {
		i_problem(gettext("Cannot remove '"), i_namep,
		    gettext("'. File modified "),
		    time_log ?
		    gettext("while disconnected.") :
		    gettext("while rolling log."),
		    NULL);
		i_resolution(gettext("Operation on '"), i_namep,
		    gettext("' skipped."), NULL);
		return (0);
	}

	// conflict if ctime changed
	else if (TIMECHANGE(ctime, va.va_ctime)) {
		i_problem(gettext("Cannot remove '"), i_namep,
		    gettext("'. File changed "),
		    time_log ?
		    gettext("while disconnected.") :
		    gettext("while rolling log."),
		    NULL);
		i_resolution(gettext("Operation on '"), i_namep,
		    gettext("' skipped."), NULL);
		return (0);
	}

	cfs_timestruc_t *ctimep = (va.va_nlink > 1) ? &i_up->dl_ctime : NULL;

	// do the remove
	xx = i_kmodp->kmod_remove(&dirfid, &i_up->dl_child_cid, i_namep,
	    &i_up->dl_cred, ctimep);
	if (xx) {
		if (TIMEDOUT(xx))
			return (ETIMEDOUT);

		// remove failed
		i_problem(gettext("Cannot remove file '"),
		    i_namep, gettext("'. Error: "),
		    strerror(xx), NULL);
		i_resolution(gettext("Operation on '"), i_namep,
		    gettext("' skipped."), NULL);
		return (0);
	}

	// record new ctime if multiple links to file
	if (ctimep) {
		i_up->dl_mtime = mtime;
		map.ms_times = i_offset +
		    offsetof(cfs_dlog_entry_t, dl_u.dl_remove.dl_times);
		xx = i_tblp->maptbl_set(&map, 1);
		if (xx)
			return (EIO);
	}

	return (0);
}

// -----------------------------------------------------------------
//
//			cfsd_logelem_remove::logelem_dump
//
// Description:
// Arguments:
// Returns:
// Preconditions:

void
cfsd_logelem_remove::logelem_dump()
{
	dbug_enter("cfsd_logelem_remove::logelem_dump");

	dbug_print("dump", ("REMOVE"));
	dbug_print("dump", ("len %d, valid %d, seq %d",
	    i_entp->dl_len, i_entp->dl_valid, i_entp->dl_seq));
	dbug_print("dump", ("file %s cid %08x, dir cid %08x",
		i_namep, i_up->dl_child_cid.cid_fileno,
		i_up->dl_parent_cid.cid_fileno));
	dbug_print("dump", ("ctime %x %x, mtime %x %x",
	    i_up->dl_ctime.tv_sec, i_up->dl_ctime.tv_nsec,
	    i_up->dl_mtime.tv_sec, i_up->dl_mtime.tv_nsec));
	i_print_cred(&i_up->dl_cred);
}

// -----------------------------------------------------------------
//
//			cfsd_logelem_rmdir::cfsd_logelem_rmdir
//
// Description:
// Arguments:
// Returns:
// Preconditions:


cfsd_logelem_rmdir::cfsd_logelem_rmdir(cfsd_maptbl *tblp,
    cfsd_logfile *lfp, cfsd_kmod *kmodp)
	: cfsd_logelem(tblp, lfp, kmodp)
{
	dbug_enter("cfsd_logelem_rmdir::cfsd_logelem_rmdir");
	i_up = &i_entp->dl_u.dl_rmdir;
	i_namep = i_up->dl_buffer +
		((i_up->dl_cred.cr_ngroups - 1) * sizeof (gid_t));
}

// -----------------------------------------------------------------
//
//			cfsd_logelem_rmdir::~cfsd_logelem_rmdir
//
// Description:
// Arguments:
// Returns:
// Preconditions:

cfsd_logelem_rmdir::~cfsd_logelem_rmdir()
{
	dbug_enter("cfsd_logelem_rmdir::~cfsd_logelem_rmdir");
}

// -----------------------------------------------------------------
//
//			cfsd_logelem_rmdir::logelem_roll
//
// Description:
// Arguments:
// Returns:
// Preconditions:

int
cfsd_logelem_rmdir::logelem_roll(u_long *)
{
	dbug_enter("cfsd_logelem_rmdir::logelem_roll");

	int xx;
	cfs_fid_t *fp;
	cfs_fid_t dirfid;
	cfs_dlog_mapping_space map;

	// get the fid of the parent directory
	xx = i_tblp->maptbl_get(i_up->dl_parent_cid, &map);
	if (xx == -1)
		return (EIO);
	if (xx || (map.ms_fid <= 0)) {
		xx = i_kmodp->kmod_cidtofid(&i_up->dl_parent_cid, &dirfid);
		if (xx) {
			i_problem(gettext("Cannot remove directory '"), i_namep,
			    gettext("'. Parent directory no longer exists"),
			    NULL);
			i_resolution(gettext("Operation on '"), i_namep,
			    gettext("' skipped."), NULL);
			return (0);
		}
	} else {
		xx = i_lfp->logfile_offset(map.ms_fid, (caddr_t *)&fp);
		if (xx)
			return (EIO);
		dirfid = *fp;
		dbug_assert(dirfid.fid_len);
	}

	// perform the rmdir
	xx = i_kmodp->kmod_rmdir(&dirfid, i_namep, &i_up->dl_cred);
	if (xx) {
		if (TIMEDOUT(xx))
			return (ETIMEDOUT);

		i_problem(gettext("Cannot remove directory '"),
		    i_namep, gettext("'. Error: "),
		    strerror(xx), NULL);
		i_resolution(gettext("Operation on '"), i_namep,
		    gettext("' skipped."), NULL);
		return (0);
	}
	return (0);
}

// -----------------------------------------------------------------
//
//			cfsd_logelem_rmdir::logelem_dump
//
// Description:
// Arguments:
// Returns:
// Preconditions:

void
cfsd_logelem_rmdir::logelem_dump()
{
	dbug_enter("cfsd_logelem_rmdir::logelem_dump");

	dbug_print("dump", ("RMDIR"));
	dbug_print("dump", ("len %d, valid %d, seq %d",
	    i_entp->dl_len, i_entp->dl_valid, i_entp->dl_seq));
	dbug_print("dump", ("dir name %s, dir cid %08x",
		i_namep, i_up->dl_parent_cid.cid_fileno));
	i_print_cred(&i_up->dl_cred);
}

// -----------------------------------------------------------------
//
//			cfsd_logelem_mkdir::cfsd_logelem_mkdir
//
// Description:
// Arguments:
// Returns:
// Preconditions:


cfsd_logelem_mkdir::cfsd_logelem_mkdir(cfsd_maptbl *tblp,
    cfsd_logfile *lfp, cfsd_kmod *kmodp)
	: cfsd_logelem(tblp, lfp, kmodp)
{
	dbug_enter("cfsd_logelem_mkdir::cfsd_logelem_mkdir");
	i_up = &i_entp->dl_u.dl_mkdir;
	i_namep = i_up->dl_buffer +
		((i_up->dl_cred.cr_ngroups - 1) * sizeof (gid_t));
}

// -----------------------------------------------------------------
//
//			cfsd_logelem_mkdir::~cfsd_logelem_mkdir
//
// Description:
// Arguments:
// Returns:
// Preconditions:

cfsd_logelem_mkdir::~cfsd_logelem_mkdir()
{
	dbug_enter("cfsd_logelem_mkdir::~cfsd_logelem_mkdir");
}

// -----------------------------------------------------------------
//
//			cfsd_logelem_mkdir::logelem_roll
//
// Description:
// Arguments:
// Returns:
// Preconditions:

int
cfsd_logelem_mkdir::logelem_roll(u_long *)
{
	dbug_enter("cfsd_logelem_mkdir::logelem_roll");

	int xx;
	cfs_fid_t *fp;
	cfs_fid_t dirfid;
	cfs_dlog_mapping_space map;

	// get the fid of the parent directory
	xx = i_tblp->maptbl_get(i_up->dl_parent_cid, &map);
	if (xx == -1)
		return (EIO);
	if (xx || (map.ms_fid <= 0)) {
		xx = i_kmodp->kmod_cidtofid(&i_up->dl_parent_cid, &dirfid);
		if (xx) {
			i_problem(gettext("Cannot create directory '"), i_namep,
			    gettext("'. Parent directory no longer exists"),
			    NULL);
			i_resolution(gettext("Operation on '"), i_namep,
			    gettext("' skipped."), NULL);
			return (0);
		}
	} else {
		xx = i_lfp->logfile_offset(map.ms_fid, (caddr_t *)&fp);
		if (xx)
			return (EIO);
		dirfid = *fp;
		dbug_assert(dirfid.fid_len);
	}

	// perform the mkdir
	xx = i_kmodp->kmod_mkdir(&dirfid, i_namep, &i_up->dl_child_cid,
		&i_up->dl_attrs, &i_up->dl_cred, &i_up->dl_fid);
	if (xx) {
		if (TIMEDOUT(xx))
			return (ETIMEDOUT);

		i_problem(gettext("Cannot create directory '"),
		    i_namep, gettext("'. Error: "),
		    strerror(xx), NULL);
		i_resolution(gettext("Operation on '"), i_namep,
		    gettext("' skipped."), NULL);
		return (0);
	}

	// update the mapping to point to the new fid
	map.ms_cid = i_up->dl_child_cid;
	map.ms_fid = i_offset +
	    offsetof(cfs_dlog_entry_t, dl_u.dl_mkdir.dl_fid);
	map.ms_times = 0;
	xx = i_tblp->maptbl_set(&map, 1);
	if (xx)
		return (EIO);

	return (0);
}

// -----------------------------------------------------------------
//
//			cfsd_logelem_mkdir::logelem_dump
//
// Description:
// Arguments:
// Returns:
// Preconditions:

void
cfsd_logelem_mkdir::logelem_dump()
{
	dbug_enter("cfsd_logelem_mkdir::logelem_dump");

	dbug_print("dump", ("MKDIR"));
	dbug_print("dump", ("len %d, valid %d, seq %d",
	    i_entp->dl_len, i_entp->dl_valid, i_entp->dl_seq));
	dbug_print("dump", ("file %s cid %08x, dir cid %08x",
		i_namep, i_up->dl_child_cid.cid_fileno,
		i_up->dl_parent_cid.cid_fileno));
	i_print_attr(&i_up->dl_attrs);
	i_print_cred(&i_up->dl_cred);
}

// -----------------------------------------------------------------
//
//			cfsd_logelem_link::cfsd_logelem_link
//
// Description:
// Arguments:
// Returns:
// Preconditions:


cfsd_logelem_link::cfsd_logelem_link(cfsd_maptbl *tblp,
    cfsd_logfile *lfp, cfsd_kmod *kmodp)
	: cfsd_logelem(tblp, lfp, kmodp)
{
	dbug_enter("cfsd_logelem_link::cfsd_logelem_link");
	i_up = &i_entp->dl_u.dl_link;
	i_namep = i_up->dl_buffer +
		((i_up->dl_cred.cr_ngroups - 1) * sizeof (gid_t));
}

// -----------------------------------------------------------------
//
//			cfsd_logelem_link::~cfsd_logelem_link
//
// Description:
// Arguments:
// Returns:
// Preconditions:

cfsd_logelem_link::~cfsd_logelem_link()
{
	dbug_enter("cfsd_logelem_link::~cfsd_logelem_link");
}

// -----------------------------------------------------------------
//
//			cfsd_logelem_link::logelem_roll
//
// Description:
// Arguments:
// Returns:
// Preconditions:

int
cfsd_logelem_link::logelem_roll(u_long *)
{
	dbug_enter("cfsd_logelem_link::logelem_roll");

	int xx;
	cfs_fid_t *fp;
	cfs_fid_t dirfid, linkfid;
	cfs_dlog_mapping_space map, dirmap;
	cfs_timestruc_t ctime, mtime;
	cfs_dlog_tm_t *tmp;

	// get the mapping for the child cid if it exists
	xx = i_tblp->maptbl_get(i_up->dl_child_cid, &map);
	if (xx == -1)
		return (EIO);

	// if a mapping was not found
	if (xx) {
		// dummy up mapping so we get values from the cache
		map.ms_cid = i_up->dl_child_cid;
		map.ms_fid = 0;
		map.ms_times = 0;
	}

	// done if there was a conflict on the file
	if (map.ms_fid == X_CONFLICT)
		return (0);

	// done if the file is optimized out
	if (map.ms_fid == X_OPTIMIZED)
		return (0);

	// if we have a fid in the mapping
	if (map.ms_fid) {
		// get the fid
		xx = i_lfp->logfile_offset(map.ms_fid, (caddr_t *)&fp);
		if (xx)
			return (EIO);
		linkfid = *fp;
		dbug_assert(linkfid.fid_len);
	}

	// else get the fid from the cache
	else {
		xx = i_kmodp->kmod_cidtofid(&i_up->dl_child_cid, &linkfid);
		if (xx == ENOENT)
			return (0);
		if (xx) {
			i_problem(gettext("Cannot link '"), i_namep,
			    gettext("'. File is no longer in the cache."),
			    NULL);
			i_resolution(gettext("Operation on '"), i_namep,
			    gettext("' skipped."), NULL);
			return (0);
		}
	}

	// if we have timestamps in the mapping
	int time_log;
	if (map.ms_times) {
		// get the times
		xx = i_lfp->logfile_offset(map.ms_times, (caddr_t *)&tmp);
		if (xx)
			return (EIO);
		ctime = tmp->tm_ctime;
		mtime = tmp->tm_mtime;
		time_log = 0;
	}

	// else get the timestamps from the log entry
	else {
		ctime = i_up->dl_ctime;
		mtime = i_up->dl_mtime;
		time_log = 1;
	}

	// get the attributes of the file from the back fs
	cfs_vattr_t va;
	xx = i_kmodp->kmod_getattrfid(&linkfid, &i_up->dl_cred, &va);
	if (TIMEDOUT(xx))
		return (ETIMEDOUT);
	if (xx) {
		i_problem(gettext("Cannot link '"), i_namep,
		    gettext("'.  Cannot get attributes on file."), NULL);
		i_resolution(gettext("Operation on '"), i_namep,
		    gettext("' skipped."), NULL);
		return (0);
	}

	// conflict if mtime changed
	if (TIMECHANGE(mtime, va.va_mtime)) {
		i_problem(gettext("Cannot link '"), i_namep,
		    gettext("'. File modified "),
		    time_log ?
		    gettext("while disconnected.") :
		    gettext("while rolling log."),
		    NULL);
		i_resolution(gettext("Operation on '"), i_namep,
		    gettext("' skipped."), NULL);
		return (0);
	}

	// conflict if ctime changed
	else if (TIMECHANGE(ctime, va.va_ctime)) {
		i_problem(gettext("Cannot link '"), i_namep,
		    gettext("'. File changed "),
		    time_log ?
		    gettext("while disconnected.") :
		    gettext("while rolling log."),
		    NULL);
		i_resolution(gettext("Operation on '"), i_namep,
		    gettext("' skipped."), NULL);
		return (0);
	}

	// get the fid of the parent directory
	xx = i_tblp->maptbl_get(i_up->dl_parent_cid, &dirmap);
	if (xx == -1)
		return (EIO);
	if (xx || (dirmap.ms_fid <= 0)) {
		xx = i_kmodp->kmod_cidtofid(&i_up->dl_parent_cid, &dirfid);
		if (xx) {
			i_problem(gettext("Cannot link '"), i_namep,
			    gettext("'. Parent directory no longer exists."),
			    NULL);
			i_resolution(gettext("Operation on '"), i_namep,
			    gettext("' skipped."), NULL);
			return (0);
		}
	} else {
		xx = i_lfp->logfile_offset(dirmap.ms_fid, (caddr_t *)&fp);
		if (xx)
			return (EIO);
		dirfid = *fp;
		dbug_assert(dirfid.fid_len);
	}

	// do the link
	xx = i_kmodp->kmod_link(&dirfid, i_namep, &linkfid, &i_up->dl_child_cid,
		&i_up->dl_cred, &i_up->dl_ctime);
	if (xx) {
		if (TIMEDOUT(xx))
			return (ETIMEDOUT);

		i_problem(gettext("Cannot link '"),
		    i_namep, gettext("'. Error: "),
		    strerror(xx), NULL);
		i_resolution(gettext("Operation on '"), i_namep,
		    gettext("' skipped."), NULL);
		return (0);
	}

	// update the mapping with the new time
	i_up->dl_mtime = mtime;
	map.ms_times = i_offset +
	    offsetof(cfs_dlog_entry_t, dl_u.dl_link.dl_times);
	xx = i_tblp->maptbl_set(&map, 1);
	if (xx)
		return (EIO);

	return (0);
}

// -----------------------------------------------------------------
//
//			cfsd_logelem_link::logelem_dump
//
// Description:
// Arguments:
// Returns:
// Preconditions:

void
cfsd_logelem_link::logelem_dump()
{
	dbug_enter("cfsd_logelem_link::logelem_dump");

	dbug_print("dump", ("LINK"));
	dbug_print("dump", ("len %d, valid %d, seq %d",
	    i_entp->dl_len, i_entp->dl_valid, i_entp->dl_seq));
	dbug_print("dump", ("cid to link %08x, dir cid %08x, name %s",
		i_up->dl_child_cid.cid_fileno,
		i_up->dl_parent_cid.cid_fileno, i_namep));
	dbug_print("dump", ("ctime %x %x, mtime %x %x",
	    i_up->dl_ctime.tv_sec, i_up->dl_ctime.tv_nsec,
	    i_up->dl_mtime.tv_sec, i_up->dl_mtime.tv_nsec));
	i_print_cred(&i_up->dl_cred);
}

// -----------------------------------------------------------------
//
//			cfsd_logelem_symlink::cfsd_logelem_symlink
//
// Description:
// Arguments:
// Returns:
// Preconditions:


cfsd_logelem_symlink::cfsd_logelem_symlink(cfsd_maptbl *tblp,
    cfsd_logfile *lfp, cfsd_kmod *kmodp)
	: cfsd_logelem(tblp, lfp, kmodp)
{
	dbug_enter("cfsd_logelem_symlink::cfsd_logelem_symlink");
	i_up = &i_entp->dl_u.dl_symlink;
	i_namep = i_up->dl_buffer +
		((i_up->dl_cred.cr_ngroups - 1) * sizeof (gid_t));
	i_contentsp = i_namep + strlen(i_namep) + 1;
}

// -----------------------------------------------------------------
//
//			cfsd_logelem_symlink::~cfsd_logelem_symlink
//
// Description:
// Arguments:
// Returns:
// Preconditions:

cfsd_logelem_symlink::~cfsd_logelem_symlink()
{
	dbug_enter("cfsd_logelem_symlink::~cfsd_logelem_symlink");
}

// -----------------------------------------------------------------
//
//			cfsd_logelem_symlink::logelem_roll
//
// Description:
// Arguments:
// Returns:
// Preconditions:

int
cfsd_logelem_symlink::logelem_roll(u_long *)
{
	dbug_enter("cfsd_logelem_symlink::logelem_roll");

	int xx;
	cfs_fid_t *fp;
	cfs_fid_t dirfid;
	cfs_dlog_mapping_space map;

	// see if the symlink no longer exists in the cache
#if 0
	xx = i_kmodp->kmod_exists(&i_up->dl_child_cid);
	if (xx) {
		dbug_assert(xx == ENOENT);

		// indicate ignore future operations on symlink
		map.ms_cid = i_up->dl_child_cid;
		map.ms_fid = X_OPTIMIZED;
		map.ms_times = 0;
		xx = i_tblp->maptbl_set(&map, 1);
		if (xx)
			return (EIO);
		return (0);
	}
#endif

	// get the fid of the parent directory
	xx = i_tblp->maptbl_get(i_up->dl_parent_cid, &map);
	if (xx == -1)
		return (EIO);
	if (xx || (map.ms_fid <= 0)) {
		xx = i_kmodp->kmod_cidtofid(&i_up->dl_parent_cid, &dirfid);
		if (xx) {
			i_problem(gettext("Cannot create symlink '"), i_namep,
			    gettext("'. Parent directory no longer exists."),
			    NULL);
			i_resolution(gettext("Operation on '"), i_namep,
			    gettext("' skipped."), NULL);
			return (0);
		}
	} else {
		xx = i_lfp->logfile_offset(map.ms_fid, (caddr_t *)&fp);
		if (xx)
			return (EIO);
		dirfid = *fp;
		dbug_assert(dirfid.fid_len);
	}

	// if the file exists on the back fs
	xx = i_kmodp->kmod_getattrname(&dirfid, i_namep, &i_up->dl_cred,
	    NULL, NULL);
	if (TIMEDOUT(xx))
		return (ETIMEDOUT);

	// if the file exists on the back file system
	if (xx == 0) {
		i_problem(gettext("Cannot create symlink '"), i_namep,
		    gettext("'. File created while disconnected"), NULL);
		i_resolution(gettext("Operation on '"), i_namep,
		    gettext("' skipped."), NULL);
		return (0);
	}

	// do the symlink
	xx = i_kmodp->kmod_symlink(&dirfid, i_namep, &i_up->dl_child_cid,
	    i_contentsp, &i_up->dl_attrs, &i_up->dl_cred,
	    &i_up->dl_fid, &i_up->dl_ctime, &i_up->dl_mtime);
	if (xx) {
		if (TIMEDOUT(xx))
			return (ETIMEDOUT);

		i_problem(gettext("Cannot create symlink '"),
		    i_namep, gettext("'. Error:."),
		    strerror(xx), NULL);
		i_resolution(gettext("Operation on '"), i_namep,
		    gettext("' skipped."), NULL);
		return (0);
	}

	// update the mapping to point to the new fid and times
	map.ms_cid = i_up->dl_child_cid;
	map.ms_fid = i_offset +
	    offsetof(cfs_dlog_entry_t, dl_u.dl_symlink.dl_fid);
	map.ms_times = i_offset +
	    offsetof(cfs_dlog_entry_t, dl_u.dl_symlink.dl_times);
	xx = i_tblp->maptbl_set(&map, 1);
	if (xx)
		return (EIO);

	return (0);
}

// -----------------------------------------------------------------
//
//			cfsd_logelem_symlink::logelem_dump
//
// Description:
// Arguments:
// Returns:
// Preconditions:

void
cfsd_logelem_symlink::logelem_dump()
{
	dbug_enter("cfsd_logelem_symlink::logelem_dump");

	dbug_print("dump", ("SYMLINK"));
	dbug_print("dump", ("len %d, valid %d, seq %d",
	    i_entp->dl_len, i_entp->dl_valid, i_entp->dl_seq));
	dbug_print("dump", ("dir cid %08x", i_up->dl_parent_cid.cid_fileno));
	dbug_print("dump", ("file cid %08x, name %s, contents %s",
		i_up->dl_child_cid.cid_fileno, i_namep, i_contentsp));
	i_print_attr(&i_up->dl_attrs);
	i_print_cred(&i_up->dl_cred);
}

// -----------------------------------------------------------------
//
//			cfsd_logelem_rename::cfsd_logelem_rename
//
// Description:
// Arguments:
// Returns:
// Preconditions:


cfsd_logelem_rename::cfsd_logelem_rename(cfsd_maptbl *tblp,
    cfsd_logfile *lfp, cfsd_kmod *kmodp)
	: cfsd_logelem(tblp, lfp, kmodp)
{
	dbug_enter("cfsd_logelem_rename::cfsd_logelem_rename");
	i_up = &i_entp->dl_u.dl_rename;
	i_orignamep = i_up->dl_buffer +
		((i_up->dl_cred.cr_ngroups - 1) * sizeof (gid_t));
	i_newnamep = i_orignamep + strlen(i_orignamep) + 1;
}

// -----------------------------------------------------------------
//
//			cfsd_logelem_rename::~cfsd_logelem_rename
//
// Description:
// Arguments:
// Returns:
// Preconditions:

cfsd_logelem_rename::~cfsd_logelem_rename()
{
	dbug_enter("cfsd_logelem_rename::~cfsd_logelem_rename");
}

// -----------------------------------------------------------------
//
//			cfsd_logelem_rename::logelem_roll
//
// Description:
// Arguments:
// Returns:
// Preconditions:

int
cfsd_logelem_rename::logelem_roll(u_long *)
{
	dbug_enter("cfsd_logelem_rename::logelem_roll");

	int xx;
	cfs_fid_t *fp;
	cfs_fid_t odirfid, ndirfid;
	cfs_dlog_mapping_space map, dirmap, delmap;
	cfs_dlog_tm_t *tmp;
	cfs_vattr_t va;
	cfs_timestruc_t mtime, ctime;
	cfs_timestruc_t delmtime, delctime;

	// get the mapping for the child cid if it exists
	xx = i_tblp->maptbl_get(i_up->dl_child_cid, &map);
	if (xx == -1)
		return (EIO);

	// if a mapping was not found
	if (xx) {
		// dummy up mapping so we get values from the cache
		map.ms_cid = i_up->dl_child_cid;
		map.ms_fid = 0;
		map.ms_times = 0;
	}

	// done if there was a conflict on the file
	if (map.ms_fid == X_CONFLICT)
		return (0);

	// done if the file is optimized out
	if (map.ms_fid == X_OPTIMIZED)
		return (0);

	// if we have timestamps in the mapping
	int time_log;
	if (map.ms_times) {
		// get the times
		xx = i_lfp->logfile_offset(map.ms_times, (caddr_t *)&tmp);
		if (xx)
			return (EIO);
		ctime = tmp->tm_ctime;
		mtime = tmp->tm_mtime;
		time_log = 0;
	}

	// else get the timestamps from the log entry
	else {
		ctime = i_up->dl_ctime;
		mtime = i_up->dl_mtime;
		time_log = 1;
	}

	// get the fid of the old parent directory
	xx = i_tblp->maptbl_get(i_up->dl_oparent_cid, &dirmap);
	if (xx == -1)
		return (EIO);
	if (xx || (dirmap.ms_fid <= 0)) {
		xx = i_kmodp->kmod_cidtofid(&i_up->dl_oparent_cid, &odirfid);
		if (xx) {
			i_problem(gettext("Cannot rename '"), i_orignamep,
			    gettext("'. Original directory no longer exists."),
			    NULL);
			i_resolution(gettext("Operation on '"), i_orignamep,
			    gettext("' skipped."), NULL);
			return (0);
		}
	} else {
		xx = i_lfp->logfile_offset(dirmap.ms_fid, (caddr_t *)&fp);
		if (xx)
			return (EIO);
		odirfid = *fp;
		dbug_assert(odirfid.fid_len);
	}

	// get the fid of the new parent directory
	xx = i_tblp->maptbl_get(i_up->dl_nparent_cid, &dirmap);
	if (xx == -1)
		return (EIO);
	if (xx || (dirmap.ms_fid <= 0)) {
		xx = i_kmodp->kmod_cidtofid(&i_up->dl_nparent_cid, &ndirfid);
		if (xx) {
			i_problem(gettext("Cannot rename '"), i_orignamep,
			    gettext("'. Target directory no longer exists."),
			    NULL);
			i_resolution(gettext("Operation on '"), i_orignamep,
			    gettext("' skipped."), NULL);
			return (0);
		}
	} else {
		xx = i_lfp->logfile_offset(dirmap.ms_fid, (caddr_t *)&fp);
		if (xx)
			return (EIO);
		ndirfid = *fp;
		dbug_assert(ndirfid.fid_len);
	}

	// get the attributes of the file from the back fs
	xx = i_kmodp->kmod_getattrname(&odirfid, i_orignamep, &i_up->dl_cred,
	    &va, NULL);
	if (TIMEDOUT(xx))
		return (ETIMEDOUT);
	if (xx) {
		i_problem(gettext("Cannot rename '"), i_orignamep,
		    gettext("'.  Cannot get attributes on file."), NULL);
		i_resolution(gettext("Operation on '"), i_orignamep,
		    gettext("' skipped."), NULL);
		return (0);
	}

	// conflict if mtime changed
	if (TIMECHANGE(mtime, va.va_mtime)) {
		i_problem(gettext("Cannot rename '"), i_orignamep,
		    gettext("'. File modified "),
		    time_log ?
		    gettext("while disconnected.") :
		    gettext("while rolling log."),
		    NULL);
		i_resolution(gettext("Operation on '"), i_orignamep,
		    gettext("' skipped."), NULL);
		return (0);
	}

	// conflict if ctime changed
	else if (TIMECHANGE(ctime, va.va_ctime)) {
		i_problem(gettext("Cannot rename '"), i_orignamep,
		    gettext("'. File changed "),
		    time_log ?
		    gettext("while disconnected.") :
		    gettext("while rolling log."),
		    NULL);
		i_resolution(gettext("Operation on '"), i_orignamep,
		    gettext("' skipped."), NULL);
		return (0);
	}

	// if we are also deleting a file
	cfs_timestruc_t *delctimep = NULL;
	if (i_up->dl_del_cid.cid_fileno != 0) {
		// get the mapping for the deleted cid if it exists
		xx = i_tblp->maptbl_get(i_up->dl_del_cid, &delmap);
		if (xx == -1)
			return (EIO);

		// if a mapping was not found
		if (xx) {
			// dummy up mapping so we get values from the cache
			delmap.ms_cid = i_up->dl_del_cid;
			delmap.ms_fid = 0;
			delmap.ms_times = 0;
		}

		// if we have timestamps in the mapping
		int time_log;
		if (delmap.ms_times) {
			// get the times
			xx = i_lfp->logfile_offset(delmap.ms_times,
			    (caddr_t *)&tmp);
			if (xx)
				return (EIO);
			delctime = tmp->tm_ctime;
			delmtime = tmp->tm_mtime;
			time_log = 0;
		}

		// else get the timestamps from the log entry
		else {
			delctime = i_up->dl_del_times.tm_ctime;
			delmtime = i_up->dl_del_times.tm_mtime;
			time_log = 1;
		}

		// get the attributes of the target file from the back fs
		xx = i_kmodp->kmod_getattrname(&ndirfid, i_newnamep,
		    &i_up->dl_cred, &va, NULL);
		if (TIMEDOUT(xx))
			return (ETIMEDOUT);
		if (xx) {
			i_problem(gettext("Cannot rename '"), i_orignamep,
			    gettext("'.  Cannot get attributes on target."),
			    NULL);
			i_resolution(gettext("Operation on '"), i_orignamep,
			    gettext("' skipped."), NULL);
			return (0);
		}

		// conflict if mtime changed
		if (TIMECHANGE(delmtime, va.va_mtime)) {
			i_problem(gettext("Cannot rename '"), i_orignamep,
			    gettext("'. Target modified "),
			    time_log ?
			    gettext("while disconnected.") :
			    gettext("while rolling log."),
			    NULL);
			i_resolution(gettext("Operation on '"), i_orignamep,
			    gettext("' skipped."), NULL);
			return (0);
		}

		// conflict if ctime changed
		else if (TIMECHANGE(delctime, va.va_ctime)) {
			i_problem(gettext("Cannot rename '"), i_orignamep,
			    gettext("'. Target changed "),
			    time_log ?
			    gettext("while disconnected.") :
			    gettext("while rolling log."),
			    NULL);
			i_resolution(gettext("Operation on '"), i_orignamep,
			    gettext("' skipped."), NULL);
			return (0);
		}

		delctimep = (va.va_nlink > 1) ? &i_up->dl_del_times.tm_ctime :
		    NULL;
	}

	// perform the rename
	xx = i_kmodp->kmod_rename(&odirfid, i_orignamep, &ndirfid, i_newnamep,
		&i_up->dl_child_cid,
		&i_up->dl_cred, &i_up->dl_ctime, delctimep, &i_up->dl_del_cid);
	if (xx) {
		if (TIMEDOUT(xx))
			return (ETIMEDOUT);

		i_problem(gettext("Cannot rename '"),
		    i_orignamep, gettext("'. Error:."),
		    strerror(xx), NULL);
		i_resolution(gettext("Operation on '"), i_orignamep,
		    gettext("' skipped."), NULL);
		return (0);
	}

	// update the mapping to point to the new times for the file
	i_up->dl_mtime = mtime;
	map.ms_times = i_offset +
	    offsetof(cfs_dlog_entry_t, dl_u.dl_rename.dl_times);
	xx = i_tblp->maptbl_set(&map, 1);
	if (xx)
		return (EIO);

	// if we deleted a file with links left
	if (delctimep) {
		// update the mapping  to the new times for the deleted file
		i_up->dl_del_times.tm_mtime = delmtime;
		delmap.ms_times = i_offset +
		    offsetof(cfs_dlog_entry_t, dl_u.dl_rename.dl_del_times);
		xx = i_tblp->maptbl_set(&delmap, 1);
		if (xx)
			return (EIO);
	}

	return (0);
}

// -----------------------------------------------------------------
//
//			cfsd_logelem_rename::logelem_dump
//
// Description:
// Arguments:
// Returns:
// Preconditions:

void
cfsd_logelem_rename::logelem_dump()
{
	dbug_enter("cfsd_logelem_rename::logelem_dump");

	dbug_print("dump", ("RENAME"));
	dbug_print("dump", ("len %d, valid %d, seq %d",
	    i_entp->dl_len, i_entp->dl_valid, i_entp->dl_seq));
	dbug_print("dump", ("orig dir cid %08x, new dir cid %08x",
		i_up->dl_oparent_cid.cid_fileno,
		i_up->dl_nparent_cid.cid_fileno));
	dbug_print("dump", ("file cid %08x", i_up->dl_child_cid.cid_fileno));
	dbug_print("dump", ("orig name '%s', new name '%s'",
		i_orignamep, i_newnamep));
	dbug_print("dump", ("file ctime %x %x, mtime %x %x",
	    i_up->dl_ctime.tv_sec, i_up->dl_ctime.tv_nsec,
	    i_up->dl_mtime.tv_sec, i_up->dl_mtime.tv_nsec));
	dbug_print("dump", ("deleted cid %08x", i_up->dl_del_cid.cid_fileno));
	dbug_print("dump", ("deleted ctime %x %x, mtime %x %x",
	    i_up->dl_del_times.tm_ctime.tv_sec,
	    i_up->dl_del_times.tm_ctime.tv_nsec,
	    i_up->dl_del_times.tm_mtime.tv_sec,
	    i_up->dl_del_times.tm_mtime.tv_nsec));
	i_print_cred(&i_up->dl_cred);
}

//
//			cfsd_logelem_modified::cfsd_logelem_modified
//
// Description:
// Arguments:
// Returns:
// Preconditions:


cfsd_logelem_modified::cfsd_logelem_modified(cfsd_maptbl *tblp,
    cfsd_logfile *lfp, cfsd_kmod *kmodp)
	: cfsd_logelem(tblp, lfp, kmodp)
{
	dbug_enter("cfsd_logelem_modified::cfsd_logelem_modified");
	i_up = &i_entp->dl_u.dl_modify;
}

//
//			cfsd_logelem_modified::~cfsd_logelem_modified
//
// Description:
// Arguments:
// Returns:
// Preconditions:

cfsd_logelem_modified::~cfsd_logelem_modified()
{
	dbug_enter("cfsd_logelem_modified::~cfsd_logelem_modified");
}

//
//			cfsd_logelem_modified::logelem_roll
//
// Description:
// Arguments:
// Returns:
// Preconditions:

int
cfsd_logelem_modified::logelem_roll(u_long *seqp)
{
	dbug_enter("cfsd_logelem_modified::logelem_roll");
	dbug_precond(seqp);

	int xx;
	cfs_fid_t filefid, *fp;
	cfs_dlog_mapping_space map;
	cfs_dlog_tm_t *tmp;
	cfs_timestruc_t ctime, mtime;
	int time_log;
	cachefsio_getinfo_t ginfo;

	// get the mapping for this cid if it exists
	xx = i_tblp->maptbl_get(i_up->dl_cid, &map);
	if (xx == -1)
		return (EIO);

	// if a mapping was not found
	if (xx) {
		// dummy up mapping so we get values from the cache
		map.ms_cid = i_up->dl_cid;
		map.ms_fid = 0;
		map.ms_times = 0;
	}

	// done if there was a conflict on the file
	if (map.ms_fid == X_CONFLICT)
		return (0);

	// done if the file is optimized out
	if (map.ms_fid == X_OPTIMIZED)
		return (0);

	// if we have a fid in the mapping
	if (map.ms_fid) {
		// get the fid
		xx = i_lfp->logfile_offset(map.ms_fid, (caddr_t *)&fp);
		if (xx)
			return (EIO);
		filefid = *fp;
		dbug_assert(filefid.fid_len);
	}

	// else get the fid from the cache
	else {
		xx = i_kmodp->kmod_cidtofid(&i_up->dl_cid, &filefid);
		if (xx == ENOENT)
			return (0);
		if (xx) {
			i_problem(gettext("Cannot write."),
			    gettext(" File is no longer in the cache."),
			    NULL);
			xx = i_lostfound(&i_up->dl_cid, NULL, NULL,
			    &i_up->dl_cred);
			return (xx);
		}
	}

	// get info about the file from the cache
	xx = i_kmodp->kmod_getinfo(&i_up->dl_cid, &ginfo);
	if (xx) {
		i_problem(gettext("Cannot write."),
		    gettext(" File is no longer in the cache."),
		    NULL);
		xx = i_lostfound(&i_up->dl_cid, NULL, NULL,
		    &i_up->dl_cred);
		return (xx);
	}

	// if we are not ready to process this write yet
	if (*seqp < ginfo.gi_seq) {
		dbug_print("info", ("Defering writing of file '%s' "
		    "current seq %d, metadata seq %d",
		    ginfo.gi_name,
		    *seqp, ginfo.gi_seq));
		*seqp = ginfo.gi_seq;
		return (EAGAIN);
	} else {
		dbug_print("info", ("Continue writing of file '%s' "
		    "current seq %d, metadata seq %d",
		    ginfo.gi_name,
		    *seqp, ginfo.gi_seq));
	}

	// if we have timestamps in the mapping
	if (map.ms_times) {
		// get the times
		xx = i_lfp->logfile_offset(map.ms_times, (caddr_t *)&tmp);
		if (xx)
			return (EIO);
		ctime = tmp->tm_ctime;
		mtime = tmp->tm_mtime;
		time_log = 0;
	}

	// else get the timestamps from the log entry
	else {
		ctime = i_up->dl_ctime;
		mtime = i_up->dl_mtime;
		time_log = 1;
	}

	// get the attributes of the file from the back fs
	cfs_vattr_t va;
	xx = i_kmodp->kmod_getattrfid(&filefid, &i_up->dl_cred, &va);
	if (TIMEDOUT(xx))
		return (ETIMEDOUT);
	if (xx) {
		xx = i_lostfound(&i_up->dl_cid, NULL, NULL, &i_up->dl_cred);
		return (xx);
	}

	int conflict = 0;

	// conflict if mtime changed
	if (TIMECHANGE(mtime, va.va_mtime)) {
		i_problem(gettext("Cannot write."),
		    gettext(" File modified "),
		    time_log ?
		    gettext("while disconnected.") :
		    gettext("while rolling log."),
		    NULL);
		conflict = 1;
	}

	// conflict if ctime changed
	else if (TIMECHANGE(ctime, va.va_ctime)) {
		i_problem(gettext("Cannot write."),
		    gettext(" File changed "),
		    time_log ?
		    gettext("while disconnected.") :
		    gettext("while rolling log."),
		    NULL);
		conflict = 1;
	}

	// if a conflict was detected
	if (conflict) {
		xx = i_lostfound(&i_up->dl_cid, NULL, NULL, &i_up->dl_cred);
		return (xx);
	}

	// now do the write, get the new times
	xx = i_kmodp->kmod_pushback(&i_up->dl_cid, &filefid, &i_up->dl_cred,
	    &i_up->dl_ctime, &i_up->dl_mtime, 1);
	if (TIMEDOUT(xx))
		return (ETIMEDOUT);
	if (xx) {
		i_problem(gettext("Write failed."),
		    gettext(" Error:"),
		    strerror(xx), NULL);
		xx = i_lostfound(&i_up->dl_cid, NULL, NULL, &i_up->dl_cred);
		return (xx);
	}

	// update the mapping to point to the new times
	map.ms_times = i_offset +
	    offsetof(cfs_dlog_entry_t, dl_u.dl_modify.dl_times);
	xx = i_tblp->maptbl_set(&map, 1);
	if (xx)
		return (EIO);
	return (0);

	return (0);
}

//
//			cfsd_logelem_modified::logelem_dump
//
// Description:
// Arguments:
// Returns:
// Preconditions:

void
cfsd_logelem_modified::logelem_dump()
{
	dbug_enter("cfsd_logelem_modified::logelem_dump");

	dbug_print("dump", ("MODIFIED"));
	dbug_print("dump", ("len %d, valid %d, seq %d",
	    i_entp->dl_len, i_entp->dl_valid, i_entp->dl_seq));
	dbug_print("dump", ("file      cid %08x", i_up->dl_cid.cid_fileno));
	dbug_print("dump", ("ctime %x %x, mtime %x %x",
	    i_up->dl_ctime.tv_sec, i_up->dl_ctime.tv_nsec,
	    i_up->dl_mtime.tv_sec, i_up->dl_mtime.tv_nsec));
	i_print_cred(&i_up->dl_cred);
}

//
//			cfsd_logelem_mapfid::cfsd_logelem_mapfid
//
// Description:
// Arguments:
// Returns:
// Preconditions:


cfsd_logelem_mapfid::cfsd_logelem_mapfid(cfsd_maptbl *tblp,
    cfsd_logfile *lfp, cfsd_kmod *kmodp)
	: cfsd_logelem(tblp, lfp, kmodp)
{
	dbug_enter("cfsd_logelem_mapfid::cfsd_logelem_mapfid");
	i_up = &i_entp->dl_u.dl_mapfid;
}

//
//			cfsd_logelem_mapfid::~cfsd_logelem_mapfid
//
// Description:
// Arguments:
// Returns:
// Preconditions:

cfsd_logelem_mapfid::~cfsd_logelem_mapfid()
{
	dbug_enter("cfsd_logelem_mapfid::~cfsd_logelem_mapfid");
}

//
//			cfsd_logelem_mapfid::logelem_roll
//
// Description:
// Arguments:
// Returns:
// Preconditions:

int
cfsd_logelem_mapfid::logelem_roll(u_long *)
{
	dbug_enter("cfsd_logelem_mapfid::logelem_roll");

	int xx;
	cfs_dlog_mapping_space map;

	// map the cid to the fid
	dbug_assert(i_up->dl_fid.fid_len);
	map.ms_cid = i_up->dl_cid;
	map.ms_fid = i_offset +
	    offsetof(cfs_dlog_entry_t, dl_u.dl_mapfid.dl_fid);
	map.ms_times = 0;

	xx = i_tblp->maptbl_set(&map, 1);
	if (xx)
		return (EIO);
	return (0);
}

//
//			cfsd_logelem_mapfid::logelem_dump
//
// Description:
// Arguments:
// Returns:
// Preconditions:

void
cfsd_logelem_mapfid::logelem_dump()
{
	dbug_enter("cfsd_logelem_mapfid::logelem_dump");

	dbug_print("dump", ("MAPFID"));
	dbug_print("dump", ("file      cid %08x", i_up->dl_cid.cid_fileno));
	i_format_fid(&i_up->dl_fid);
	dbug_print("dump", ("fid '%s'", i_fidbuf));
}
