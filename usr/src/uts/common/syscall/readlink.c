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
 */

/*	Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * Portions of this source code were derived from Berkeley 4.3 BSD
 * under license from the Regents of the University of California.
 */

#include <sys/param.h>
#include <sys/isa_defs.h>
#include <sys/types.h>
#include <sys/sysmacros.h>
#include <sys/cred.h>
#include <sys/systm.h>
#include <sys/errno.h>
#include <sys/pathname.h>
#include <sys/vnode.h>
#include <sys/file.h>
#include <sys/fcntl.h>
#include <sys/uio.h>
#include <sys/debug.h>
#include <fs/fs_subr.h>
#include <c2/audit.h>

/*
 * Read the contents of a symbolic link.
 */
ssize_t
readlinkat(int dfd, char *name, char *buf, size_t count)
{
	vnode_t *startvp;
	vnode_t *vp;
	struct iovec aiov;
	struct uio auio;
	int error;
	struct vattr vattr;
	ssize_t cnt;
	int estale_retry = 0;

	if ((cnt = (ssize_t)count) < 0)
		return (set_errno(EINVAL));
	if (name == NULL)
		return (set_errno(EFAULT));
	if ((error = fgetstartvp(dfd, name, &startvp)) != 0)
		return (set_errno(error));

lookup:
	if (AU_AUDITING() && startvp != NULL)
		audit_setfsat_path(1);
	if (error = lookupnameat(name, UIO_USERSPACE, NO_FOLLOW,
	    NULLVPP, &vp, startvp)) {
		if (error == ESTALE && fs_need_estale_retry(estale_retry++))
			goto lookup;
		goto out;
	}

	if (vp->v_type != VLNK) {
		/*
		 * Ask the underlying filesystem if it wants this
		 * object to look like a symlink at user-level.
		 */
		vattr.va_mask = AT_TYPE;
		error = VOP_GETATTR(vp, &vattr, 0, CRED(), NULL);
		if (error || vattr.va_type != VLNK) {
			VN_RELE(vp);
			if ((error == ESTALE) &&
			    fs_need_estale_retry(estale_retry++))
				goto lookup;
			error = EINVAL;
			goto out;
		}
	}
	aiov.iov_base = buf;
	aiov.iov_len = cnt;
	auio.uio_iov = &aiov;
	auio.uio_iovcnt = 1;
	auio.uio_loffset = 0;
	auio.uio_segflg = UIO_USERSPACE;
	auio.uio_extflg = UIO_COPY_CACHED;
	auio.uio_resid = cnt;
	error = VOP_READLINK(vp, &auio, CRED(), NULL);
	VN_RELE(vp);
	if (error == ESTALE && fs_need_estale_retry(estale_retry++))
		goto lookup;
out:
	if (startvp != NULL)
		VN_RELE(startvp);
	if (error)
		return (set_errno(error));
	return ((ssize_t)(cnt - auio.uio_resid));
}

ssize_t
readlink(char *name, char *buf, size_t count)
{
	return (readlinkat(AT_FDCWD, name, buf, count));
}

#ifdef _SYSCALL32_IMPL
/*
 * readlink32() intentionally returns a ssize_t rather than ssize32_t;
 * see the comments above read32 for details.
 */

ssize_t
readlinkat32(int dfd, caddr32_t name, caddr32_t buf, size32_t count)
{
	return ((ssize32_t)readlinkat(dfd, (char *)(uintptr_t)name,
	    (char *)(uintptr_t)buf, (ssize32_t)count));
}

ssize_t
readlink32(caddr32_t name, caddr32_t buf, size32_t count)
{
	return ((ssize32_t)readlinkat(AT_FDCWD, (char *)(uintptr_t)name,
	    (char *)(uintptr_t)buf, (ssize32_t)count));
}

#endif	/* _SYSCALL32_IMPL */
