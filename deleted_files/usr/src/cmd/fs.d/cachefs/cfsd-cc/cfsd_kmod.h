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
//			cfsd_kmod.h
//
// Include file for the cfsd_kmod class.
//

#pragma ident	"%Z%%M%	%I%	%E% SMI"
// Copyright (c) 1994-1997 by Sun Microsystems, Inc.
// All rights reserved.

#ifndef CFSD_KMOD
#define	CFSD_KMOD

class cfsd_kmod {
private:
	RWCString		i_path;		// path to root of file system
	int			i_fd;		// file descriptor of i_path
	char			i_fidbuf[1024];	// for formatted fid

	void i_format_fid(const cfs_fid_t *fidp);
	void i_print_cred(const cred_t *credp);
	void i_print_attr(const cfs_vattr_t *vattrp);
	int  i_doioctl(enum cfsdcmd_cmds cmd, void *sdata, int slen,
	    void *rdata, int rlen);

public:
	cfsd_kmod();
	~cfsd_kmod();
	int kmod_setup(const char *path);
	void kmod_shutdown();
	int kmod_xwait();
	int kmod_stateget();
	int kmod_stateset(int state);
	int kmod_exists(cfs_cid *cidp);
	int kmod_lostfound(cfs_cid *cidp, const char *namep, char *newnamep);
	int kmod_lostfoundall();
	int kmod_rofs();
	int kmod_rootfid(cfs_fid_t *fidp);
	int kmod_getstats(cachefsio_getstats_t *);
	int kmod_getinfo(cfs_cid_t *filep, cachefsio_getinfo *infop);
	int kmod_cidtofid(cfs_cid *cidp, cfs_fid_t *fidp);
	int kmod_getattrfid(cfs_fid_t *fidp, cred_t *credp, cfs_vattr_t *vattrp);
	int kmod_getattrname(cfs_fid_t *dirp, const char *name, cred_t *credp,
		cfs_vattr_t *vattrp, cfs_fid_t *filep);
	int kmod_create(cfs_fid_t *dirp, const char *namep, const cfs_cid_t *cidp,
		cfs_vattr_t *vattrp, int exclusive, int mode, cred_t *credp,
		cfs_fid_t *newfidp, cfs_timestruc_t *ctimep, cfs_timestruc_t *mtimep);
	int kmod_pushback(cfs_cid *filep, cfs_fid_t *fidp, cred_t *credp,
		cfs_timestruc_t *ctimep, cfs_timestruc_t *mtimep, int update);
	int kmod_rename(cfs_fid_t *olddir, const char *oldname, cfs_fid_t *newdir,
		const char *newname, const cfs_cid_t *cidp, cred_t *credp,
		cfs_timestruc_t *ctimep, cfs_timestruc_t *delctimep,
		const cfs_cid_t *delcidp);
	int kmod_setattr(cfs_fid_t *fidp, const cfs_cid_t *cidp, cfs_vattr_t *vattrp,
		int flags,
		cred_t *credp, cfs_timestruc_t *ctimep, cfs_timestruc_t *mtimep);
	int kmod_setsecattr(cfs_fid_t *fidp, const cfs_cid_t *cidp, u_long mask,
		int aclcnt, int dfaclcnt, const aclent_t *acl, cred_t *credp,
		cfs_timestruc_t *ctimep, cfs_timestruc_t *mtimep);
	int kmod_remove(const cfs_fid_t *fidp, const cfs_cid_t *cidp,
		const char *namep, const cred_t *credp, cfs_timestruc_t *ctimep);
	int kmod_link(const cfs_fid_t *dirfidp, const char *namep,
		const cfs_fid_t *filefidp, const cfs_cid_t *cidp,
		const cred_t *credp, cfs_timestruc_t *ctimep);
	int kmod_mkdir(const cfs_fid_t *dirfidp, const char *namep,
		const cfs_cid_t *cidp,
		const cfs_vattr_t *vattrp, const cred_t *credp, cfs_fid_t *newfidp);
	int kmod_rmdir(const cfs_fid_t *dirfidp, const char *namep,
		const cred_t *credp);
	int kmod_symlink(const cfs_fid_t *dirfidp, const char *namep,
		const cfs_cid_t *cidp,
		const char *linkvalp, const cfs_vattr_t *vattrp,
		const cred_t *credp,
		cfs_fid_t *newfidp, cfs_timestruc_t *ctimep, cfs_timestruc_t *mtimep);
};

#endif /* CFSD_KMOD */
