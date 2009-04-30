/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
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
 * High Sierra filesystem internal routine definitions.
 */
/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_FS_HSFS_IMPL_H
#define	_SYS_FS_HSFS_IMPL_H

#include <sys/vfs_opreg.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * global routines.
 */

extern int hsfs_putapage(vnode_t *, page_t *, u_offset_t *, size_t *, int,
	cred_t *);
/* read a sector */
extern int hs_readsector(struct vnode *vp, uint_t secno, uchar_t *ptr);
/* lookup/construct an hsnode/vnode */
extern struct vnode *hs_makenode(struct hs_direntry *dp,
	uint_t lbn, uint_t off, struct vfs *vfsp);
/* make hsnode from directory lbn/off */
extern int hs_remakenode(uint_t lbn, uint_t off, struct vfs *vfsp,
	struct vnode **vpp);
/* lookup name in directory */
extern int hs_dirlook(struct vnode *dvp, char *name, int namlen,
	struct vnode **vpp, struct cred *cred);
/* find an hsnode in the hash list */
extern struct vnode *hs_findhash(ino64_t nodeid, uint_t lbn, uint_t off,
	struct vfs *vfsp);
/* destroy an hsnode */
extern void hs_freenode(vnode_t *vp, struct hsfs *fsp, int nopage);
/* parse a directory entry */
extern int hs_parsedir(struct hsfs *fsp, uchar_t *dirp,
	struct hs_direntry *hdp, char *dnp, int *dnlen, int last_offset);
/* convert d-characters */
extern int hs_namecopy(char *from, char *to, int size, ulong_t flags);
extern int hs_jnamecopy(char *from, char *to, int size, int maxsize,
	ulong_t flags);
extern int hs_joliet_cp(char *from, char *to, int size);
/* destroy the incore hnode table */
extern void hs_filldirent(struct vnode *vp, struct hs_direntry *hdp);
/* check vnode protection */
extern int hs_access(struct vnode *vp, mode_t m, struct cred *cred);

extern int hs_synchash(struct vfs *vfsp);

extern void hs_parse_dirdate(uchar_t *dp, struct timeval *tvp);
extern void hs_parse_longdate(uchar_t *dp, struct timeval *tvp);
extern int hs_uppercase_copy(char *from, char *to, int size);
extern void hs_log_bogus_disk_warning(struct hsfs *fsp, int errtype,
	uint_t data);
extern int hsfs_valid_dir(struct hs_direntry *hd);
extern void hs_init_hsnode_cache(void);
extern void hs_fini_hsnode_cache(void);

/*
 * Global data structures
 */
extern const struct fs_operation_def hsfs_vnodeops_template[];
extern struct vnodeops *hsfs_vnodeops;
extern kmutex_t hs_mounttab_lock;
extern struct hsfs *hs_mounttab;

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_FS_HSFS_IMPL_H */
