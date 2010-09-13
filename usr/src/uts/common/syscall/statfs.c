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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * Portions of this source code were derived from Berkeley 4.3 BSD
 * under license from the Regents of the University of California.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/inttypes.h>
#include <sys/types.h>
#include <sys/t_lock.h>
#include <sys/param.h>
#include <sys/errno.h>
#include <sys/fstyp.h>
#include <sys/systm.h>
#include <sys/vfs.h>
#include <sys/statfs.h>
#include <sys/vnode.h>
#include <sys/file.h>
#include <sys/cmn_err.h>
#include <sys/debug.h>
#include <sys/pathname.h>

#include <vm/page.h>
#include <fs/fs_subr.h>

#if defined(_SYSCALL32_IMPL) || defined(_ILP32)

/*
 * statfs(2) and fstatfs(2) have been replaced by statvfs(2) and
 * fstatvfs(2) and will be removed from the system in a near-future
 * release.
 *
 * Supported here purely for 32-bit compatibility.
 */

static int cstatfs(struct vfs *, struct statfs32 *, int);

int
statfs32(char *fname, struct statfs32 *sbp, int32_t len, int32_t fstyp)
{
	vnode_t *vp;
	int error;
	int estale_retry = 0;

lookup:
	if (error = lookupname(fname, UIO_USERSPACE, FOLLOW, NULLVPP, &vp)) {
		if ((error == ESTALE) && fs_need_estale_retry(estale_retry++))
			goto lookup;
		return (set_errno(error));
	}
	if (fstyp != 0)
		error = EINVAL;
	else
		error = cstatfs(vp->v_vfsp, sbp, len);
	VN_RELE(vp);
	if (error) {
		if ((error == ESTALE) && fs_need_estale_retry(estale_retry++))
			goto lookup;
		return (set_errno(error));
	}
	return (0);
}

int
fstatfs32(int32_t fdes, struct statfs32 *sbp, int32_t len, int32_t fstyp)
{
	struct file *fp;
	int error;

	if (fstyp != 0)
		return (set_errno(EINVAL));
	if ((fp = getf(fdes)) == NULL)
		return (set_errno(EBADF));
	error = cstatfs(fp->f_vnode->v_vfsp, sbp, len);
	releasef(fdes);
	if (error)
		return (set_errno(error));
	return (0);
}

/*
 * Common routine for fstatfs and statfs.
 */
static int
cstatfs(struct vfs *vfsp, struct statfs32 *sbp, int len)
{
	struct statfs32 sfs;
	struct statvfs64 svfs;
	int error, i;
	char *cp, *cp2;
	struct vfssw *vswp;

	if (len < 0 || len > sizeof (struct statfs))
		return (EINVAL);
	if (error = VFS_STATVFS(vfsp, &svfs))
		return (error);

	if (svfs.f_blocks > UINT32_MAX || svfs.f_bfree > UINT32_MAX ||
	    svfs.f_files > UINT32_MAX || svfs.f_ffree > UINT32_MAX)
	    return (EOVERFLOW);
	/*
	 * Map statvfs fields into the old statfs structure.
	 */
	bzero(&sfs, sizeof (sfs));
	sfs.f_bsize = svfs.f_bsize;
	sfs.f_frsize = (svfs.f_frsize == svfs.f_bsize) ? 0 : svfs.f_frsize;
	sfs.f_blocks = svfs.f_blocks * (svfs.f_frsize / 512);
	sfs.f_bfree = svfs.f_bfree * (svfs.f_frsize / 512);
	sfs.f_files = svfs.f_files;
	sfs.f_ffree = svfs.f_ffree;

	cp = svfs.f_fstr;
	cp2 = sfs.f_fname;
	i = 0;
	while (i++ < sizeof (sfs.f_fname))
		if (*cp != '\0')
			*cp2++ = *cp++;
		else
			*cp2++ = '\0';
	while (*cp != '\0' &&
	    i++ < (sizeof (svfs.f_fstr) - sizeof (sfs.f_fpack)))
		cp++;
	(void) strncpy(sfs.f_fpack, cp + 1, sizeof (sfs.f_fpack));
	if ((vswp = vfs_getvfssw(svfs.f_basetype)) == NULL)
		sfs.f_fstyp = 0;
	else {
		sfs.f_fstyp = vswp - vfssw;
		vfs_unrefvfssw(vswp);
	}

	if (copyout(&sfs, sbp, len))
		return (EFAULT);

	return (0);
}

#endif	/* _SYSCALL32_IMPL || _ILP32 */
