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
 * Copyright (c) 1994, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2017 Nexenta Systems, Inc.  All rights reserved.
 */

/*	Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved	*/

/*
 * Portions of this source code were derived from Berkeley 4.3 BSD
 * under license from the Regents of the University of California.
 */

/*
 * Get file attribute information through a file name or a file descriptor.
 */

#include <sys/param.h>
#include <sys/isa_defs.h>
#include <sys/types.h>
#include <sys/sysmacros.h>
#include <sys/cred.h>
#include <sys/systm.h>
#include <sys/errno.h>
#include <sys/fcntl.h>
#include <sys/pathname.h>
#include <sys/stat.h>
#include <sys/vfs.h>
#include <sys/vnode.h>
#include <sys/mode.h>
#include <sys/file.h>
#include <sys/proc.h>
#include <sys/uio.h>
#include <sys/debug.h>
#include <sys/cmn_err.h>
#include <fs/fs_subr.h>

#include <libfksmbfs.h>

int
fake_stat(vnode_t *vp, struct stat64 *ubp, int flag)
{
	cred_t *cr = CRED();
	struct vfssw *vswp;
	struct stat64 lsb;
	vattr_t vattr;
	int error;

	vattr.va_mask = AT_STAT | AT_NBLOCKS | AT_BLKSIZE | AT_SIZE;
	if (error = VOP_GETATTR(vp, &vattr, flag, cr, NULL))
		return (error);

	bzero(&lsb, sizeof (lsb));
	lsb.st_dev = vattr.va_fsid;
	lsb.st_ino = vattr.va_nodeid;
	lsb.st_mode = VTTOIF(vattr.va_type) | vattr.va_mode;
	lsb.st_nlink = vattr.va_nlink;
	lsb.st_uid = vattr.va_uid;
	lsb.st_gid = vattr.va_gid;
	lsb.st_rdev = vattr.va_rdev;
	lsb.st_size = vattr.va_size;
	lsb.st_atim = vattr.va_atime;
	lsb.st_mtim = vattr.va_mtime;
	lsb.st_ctim = vattr.va_ctime;
	lsb.st_blksize = vattr.va_blksize;
	lsb.st_blocks = vattr.va_nblocks;
	if (vp->v_vfsp != NULL) {
		vswp = &vfssw[vp->v_vfsp->vfs_fstype];
		if (vswp->vsw_name && *vswp->vsw_name)
			(void) strcpy(lsb.st_fstype, vswp->vsw_name);
	}
	if (copyout(&lsb, ubp, sizeof (lsb)))
		return (EFAULT);
	return (0);
}
