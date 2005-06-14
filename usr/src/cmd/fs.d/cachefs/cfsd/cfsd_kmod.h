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
 * Copyright 1994-1997,2002-2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 *			cfsd_kmod.h
 *
 * Include file for the cfsd_kmod class.
 *
 */

#ifndef _CFSD_KMOD
#define	_CFSD_KMOD

#pragma ident	"%Z%%M%	%I%	%E% SMI"

typedef struct cfsd_kmod_object {
	char	i_path[MAXPATHLEN];	/* path to root of file system */
	int	i_fd;			/* file descriptor of i_path */
#ifndef DBUG_OFF
	char	i_fidbuf[1024];		/* for formatted fid */
#endif
}cfsd_kmod_object_t;

cfsd_kmod_object_t *cfsd_kmod_create(void);
void cfsd_kmod_destroy(cfsd_kmod_object_t *kmod_object_p);
int kmod_setup(cfsd_kmod_object_t *kmod_object_p, const char *path);
void kmod_shutdown(cfsd_kmod_object_t *kmod_object_p);
int kmod_xwait(cfsd_kmod_object_t *kmod_object_p);
int kmod_stateget(cfsd_kmod_object_t *kmod_object_p);
int kmod_stateset(cfsd_kmod_object_t *kmod_object_p, int state);
int kmod_exists(cfsd_kmod_object_t *kmod_object_p, cfs_cid_t *cidp);
int kmod_lostfound(cfsd_kmod_object_t *kmod_object_p, cfs_cid_t *cidp,
    const char *namep, char *newnamep);
int kmod_lostfoundall(cfsd_kmod_object_t *kmod_object_p);
int kmod_rofs(cfsd_kmod_object_t *kmod_object_p);
int kmod_rootfid(cfsd_kmod_object_t *kmod_object_p, cfs_fid_t *fidp);
int kmod_getstats(cfsd_kmod_object_t *kmod_object_p, cachefsio_getstats_t *gsp);
int kmod_getinfo(cfsd_kmod_object_t *kmod_object_p, cfs_cid_t *filep,
    cachefsio_getinfo_t *infop);
int kmod_cidtofid(cfsd_kmod_object_t *kmod_object_p,
    cfs_cid_t *cidp, cfs_fid_t *fidp);
int kmod_getattrfid(cfsd_kmod_object_t *kmod_object_p, cfs_fid_t *fidp,
    dl_cred_t *credp, cfs_vattr_t *vattrp);
int kmod_getattrname(cfsd_kmod_object_t *kmod_object_p, cfs_fid_t *dirp,
    const char *name, dl_cred_t *credp, cfs_vattr_t *vattrp, cfs_fid_t *filep);
int kmod_create(cfsd_kmod_object_t *kmod_object_p, cfs_fid_t *dirp,
    const char *namep, const cfs_cid_t *cidp, cfs_vattr_t *vattrp,
    int exclusive, int mode, dl_cred_t *credp, cfs_fid_t *newfidp,
    timestruc_t *ctimep, timestruc_t *mtimep);
int kmod_pushback(cfsd_kmod_object_t *kmod_object_p, cfs_cid_t *filep,
    cfs_fid_t *fidp, dl_cred_t *credp, timestruc_t *ctimep, timestruc_t *mtimep,
    int update);
int kmod_rename(cfsd_kmod_object_t *kmod_object_p, cfs_fid_t *olddir,
    const char *oldname, cfs_fid_t *newdir, const char *newname,
    const cfs_cid_t *cidp, dl_cred_t *credp, timestruc_t *ctimep,
    timestruc_t *delctimep, const cfs_cid_t *delcidp);
int kmod_setattr(cfsd_kmod_object_t *kmod_object_p, cfs_fid_t *fidp,
    const cfs_cid_t *cidp, cfs_vattr_t *vattrp, int flags, dl_cred_t *credp,
    timestruc_t *ctimep, timestruc_t *mtimep);
int kmod_setsecattr(cfsd_kmod_object_t *kmod_object_p, cfs_fid_t *fidp,
    const cfs_cid_t *cidp, ulong_t mask, int aclcnt, int dfaclcnt,
    const aclent_t *acl, dl_cred_t *credp, timestruc_t *ctimep,
    timestruc_t *mtimep);
int kmod_remove(cfsd_kmod_object_t *kmod_object_p, const cfs_fid_t *fidp,
    const cfs_cid_t *cidp, const char *namep, const dl_cred_t *credp,
    timestruc_t *ctimep);
int kmod_link(cfsd_kmod_object_t *kmod_object_p, const cfs_fid_t *dirfidp,
    const char *namep, const cfs_fid_t *filefidp, const cfs_cid_t *cidp,
    const dl_cred_t *credp, timestruc_t *ctimep);
int kmod_mkdir(cfsd_kmod_object_t *kmod_object_p, const cfs_fid_t *dirfidp,
    const char *namep, const cfs_cid_t *cidp, const cfs_vattr_t *vattrp,
    const dl_cred_t *credp, cfs_fid_t *newfidp);
int kmod_rmdir(cfsd_kmod_object_t *kmod_object_p, const cfs_fid_t *dirfidp,
    const char *namep, const dl_cred_t *credp);
int kmod_symlink(cfsd_kmod_object_t *kmod_object_p, const cfs_fid_t *dirfidp,
    const char *namep, const cfs_cid_t *cidp, const char *linkvalp,
    const cfs_vattr_t *vattrp, const dl_cred_t *credp, cfs_fid_t *newfidp,
    timestruc_t *ctimep, timestruc_t *mtimep);
#ifndef DBUG_OFF
void kmod_format_fid(cfsd_kmod_object_t *kmod_object_p, const cfs_fid_t *fidp);
void kmod_print_cred(const dl_cred_t *credp);
void kmod_print_attr(const vattr_t *vp);
#else
#define	kmod_format_fid(A, B)	0
#define	kmod_print_cred(A)	0
#define	kmod_print_attr(A)	0
#endif /* DBUG_OFF */
int  kmod_doioctl(cfsd_kmod_object_t *kmod_object_p, enum cfsdcmd_cmds cmd,
    void *sdata, int slen, void *rdata, int rlen);

#endif	/* _CFSD_KMOD */
