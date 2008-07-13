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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * Portions of this source code were derived from Berkeley 4.3 BSD
 * under license from the Regents of the University of California.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/param.h>
#include <sys/isa_defs.h>
#include <sys/types.h>
#include <sys/sysmacros.h>
#include <sys/cred.h>
#include <sys/systm.h>
#include <sys/errno.h>
#include <sys/pathname.h>
#include <sys/vnode.h>
#include <sys/vfs.h>
#include <sys/file.h>
#include <sys/uio.h>
#include <sys/debug.h>
#include <fs/fs_subr.h>

/*
 * Common code for pathconf(), fpathconf() system calls
 */
static long
cpathconf(register vnode_t *vp, int cmd, struct cred *cr)
{
	struct statvfs64 sb;
	int error;
	ulong_t val;

	switch (cmd) {
	case _PC_2_SYMLINKS:
		if (error = VOP_PATHCONF(vp, _PC_SYMLINK_MAX, &val, cr, NULL))
			return ((long)set_errno(error));
		return ((long)(val > 0));

	case _PC_ALLOC_SIZE_MIN:
	case _PC_REC_INCR_XFER_SIZE:
	case _PC_REC_MAX_XFER_SIZE:
	case _PC_REC_MIN_XFER_SIZE:
	case _PC_REC_XFER_ALIGN:
		if ((error = VFS_STATVFS(vp->v_vfsp, &sb)) != 0)
			return ((long)set_errno(error));

		/*
		 * There is generally no harm in doing larger transfers, but
		 * there's a point of diminishing returns.  With 1MB transfers,
		 * even if they're random, you get very close to platter speed.
		 * Se we return 1MB as the maximum transfer size.
		 */
		if (cmd == _PC_REC_MAX_XFER_SIZE)
			return ((long)MAX(sb.f_bsize, 1UL << 20));

		/*
		 * By definition, f_frsize is the smallest filesystem block.
		 * However, _PC_ALLOC_SIZE_MIN is intended to define the
		 * threshold for direct I/O.  This implies two requirements:
		 * the VM and I/O subsystems must be able to create mappings
		 * for DMA, which requires at least page alignment; and the
		 * filesystem must avoid read/modify/write, which generally
		 * requires multiples of its 'preferred' blocksize, f_bsize.
		 *
		 * PAGESIZE alignment is sufficient for DMA and block copy.
		 * Rounding up to the filesystem 'preferred' blocksize
		 * works just as well.
		 *
		 * All together, this means that the remaining parameters
		 * map into the same value.
		 */
		return ((long)MAX(sb.f_bsize, PAGESIZE));

	case _PC_ASYNC_IO:
		return (1l);

	case _PC_PRIO_IO:
		return ((long)set_errno(EINVAL));

	case _PC_SYNC_IO:
		if (!(error = VOP_FSYNC(vp, FSYNC, cr, NULL)))
			return (1l);
		return ((long)set_errno(error));

	case _PC_XATTR_ENABLED:
		return ((vp->v_vfsp->vfs_flag & VFS_XATTR) ? 1 : 0);

	default:
		if (error = VOP_PATHCONF(vp, cmd, &val, cr, NULL))
			return ((long)set_errno(error));
		return (val);
	}
	/* NOTREACHED */
}

/* fpathconf/pathconf interfaces */

long
fpathconf(int fdes, int name)
{
	file_t *fp;
	long retval;

	if ((fp = getf(fdes)) == NULL)
		return (set_errno(EBADF));
	retval = cpathconf(fp->f_vnode, name, fp->f_cred);
	releasef(fdes);
	return (retval);
}

long
pathconf(char *fname, int name)
{
	vnode_t *vp;
	long	retval;
	int	error;
	int 	estale_retry = 0;

lookup:
	if (error = lookupname(fname, UIO_USERSPACE, FOLLOW, NULLVPP, &vp)) {
		if ((error == ESTALE) && fs_need_estale_retry(estale_retry++))
			goto lookup;
		return ((long)set_errno(error));
	}

	retval = cpathconf(vp, name, CRED());
	VN_RELE(vp);
	return (retval);
}
