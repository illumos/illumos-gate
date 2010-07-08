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
#include <sys/systm.h>
#include <sys/errno.h>
#include <sys/pathname.h>
#include <sys/vfs.h>
#include <sys/vnode.h>
#include <sys/file.h>
#include <sys/fcntl.h>
#include <sys/proc.h>
#include <sys/uio.h>
#include <sys/debug.h>
#include <c2/audit.h>
#include <fs/fs_subr.h>

/*
 * Create a symbolic link.  Similar to link or rename except target
 * name is passed as string argument, not converted to vnode reference.
 */
int
symlinkat(char *target, int dfd, char *linkname)
{
	vnode_t *startvp;
	vnode_t *dvp;
	struct vattr vattr;
	struct pathname lpn;
	char *tbuf;
	size_t tlen;
	int error;
	int estale_retry = 0;
	int auditing = AU_AUDITING();

	if (linkname == NULL)
		return (set_errno(EFAULT));
	if ((error = fgetstartvp(dfd, linkname, &startvp)) != 0)
		return (set_errno(error));

top:
	if (error = pn_get(linkname, UIO_USERSPACE, &lpn))
		goto out;
	if (auditing && startvp != NULL)
		audit_setfsat_path(2);
	if (error = lookuppnat(&lpn, NULL, NO_FOLLOW, &dvp, NULLVPP, startvp)) {
		pn_free(&lpn);
		if (error == ESTALE && fs_need_estale_retry(estale_retry++))
			goto top;
		goto out;
	}
	if (vn_is_readonly(dvp))
		error = EROFS;
	else if (pn_fixslash(&lpn))
		error = ENOTDIR;
	else {
		tbuf = kmem_alloc(MAXPATHLEN, KM_SLEEP);
		if ((error = copyinstr(target, tbuf, MAXPATHLEN, &tlen)) == 0) {
			vattr.va_type = VLNK;
			vattr.va_mode = 0777;
			vattr.va_mask = AT_TYPE|AT_MODE;
			error = VOP_SYMLINK(dvp, lpn.pn_path, &vattr,
			    tbuf, CRED(), NULL, 0);
			if (auditing)
				audit_symlink_create(dvp, lpn.pn_path,
				    tbuf, error);
		}
		kmem_free(tbuf, MAXPATHLEN);
	}
	pn_free(&lpn);
	VN_RELE(dvp);
	if (error == ESTALE && fs_need_estale_retry(estale_retry++))
		goto top;
out:
	if (startvp != NULL)
		VN_RELE(startvp);
	if (error)
		return (set_errno(error));
	return (0);
}

int
symlink(char *target, char *linkname)
{
	return (symlinkat(target, AT_FDCWD, linkname));
}
