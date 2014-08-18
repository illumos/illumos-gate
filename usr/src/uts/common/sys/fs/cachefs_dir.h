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
 * Copyright 2014 Garrett D'Amore <garrett@damore.org>
 *
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SYS_FS_CACHEFS_DIR_H
#define	_SYS_FS_CACHEFS_DIR_H

#include <sys/types.h>
#include <sys/fs/cachefs_fs.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * c_dirent is stored on disk, so it needs to be the same 32-bit vs. 64-bit.
 */

#if _LONG_LONG_ALIGNMENT == 8 && _LONG_LONG_ALIGNMENT_32 == 4
#pragma pack(4)
#endif

struct c_dirent {
	uint_t		d_length;	/* entry length */
	uint_t		d_flag;		/* entry flags */
	cfs_cid_t	d_id;		/* file id */
	offset_t	d_offset;	/* disk offset of this entry */
	cfs_fid_t	d_cookie;	/* back fid */
	ushort_t	d_namelen;	/* name length, without null */
	char		d_name[1];	/* name */
};

#if _LONG_LONG_ALIGNMENT == 8 && _LONG_LONG_ALIGNMENT_32 == 4
#pragma pack()
#endif

#define	C_DIRSIZ(dp) \
	(((dp)->d_namelen + (uint_t)sizeof (struct c_dirent) + 7) & ~7)

#define	CDE_SIZE(NM) \
	((strlen(NM) + sizeof (struct c_dirent) + 7) & ~7)

/*
 * Various flags stored in c_dirent flag field.
 */
#define	CDE_VALID	0x1		/* entry is valid */
#define	CDE_COMPLETE	0x2		/* entry is complete */


#if defined(_KERNEL)
int cachefs_dir_look(cnode_t *dcp, char *nm, fid_t *cookiep, uint_t *flagp,
    u_offset_t *d_offsetp, cfs_cid_t *cidp);
int cachefs_dir_new(cnode_t *dcp, cnode_t *cp);
int cachefs_dir_enter(cnode_t *dcp, char *nm, fid_t *cookiep, cfs_cid_t *cidp,
    int issync);
int cachefs_dir_rmentry(cnode_t *dcp, char *nm);
void cachefs_dir_modentry(cnode_t *dcp, u_offset_t offset, fid_t *cookiep,
    cfs_cid_t *cidp);
int cachefs_dir_read(struct cnode *dcp, struct uio *uiop, int *eofp);
int cachefs_dir_fill(cnode_t *dcp, cred_t *cr);
int cachefs_dir_empty(cnode_t *dcp);
int cachefs_async_populate_dir(struct cachefs_populate_req *, cred_t *,
    vnode_t *, vnode_t *);

#endif /* defined(_KERNEL) */

#ifdef __cplusplus
}
#endif

#endif /* _SYS_FS_CACHEFS_DIR_H */
