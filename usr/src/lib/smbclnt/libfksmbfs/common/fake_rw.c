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
 * Copyright (c) 2015, Joyent, Inc.  All rights reserved.
 * Copyright 2017 Nexenta Systems, Inc.  All rights reserved.
 */

/*	Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * Portions of this source code were derived from Berkeley 4.3 BSD
 * under license from the Regents of the University of California.
 */

#include <sys/param.h>
#include <sys/types.h>
#include <sys/inttypes.h>
#include <sys/sysmacros.h>
#include <sys/cred.h>
#include <sys/user.h>
#include <sys/systm.h>
#include <sys/errno.h>
#include <sys/vnode.h>
#include <sys/file.h>
#include <sys/proc.h>
#include <sys/uio.h>
#include <sys/debug.h>

#include <libfksmbfs.h>

#define	set_errno(e) (-(e))

ssize_t
fake_pread(vnode_t *vp, void *cbuf, size_t count, off_t offset)
{
	struct uio auio;
	struct iovec aiov;
	int fflag, ioflag, rwflag;
	ssize_t bcount;
	int error = 0;
	u_offset_t fileoff = (u_offset_t)(ulong_t)offset;
	const u_offset_t maxoff = MAXOFF32_T;

	if ((bcount = (ssize_t)count) < 0)
		return (set_errno(EINVAL));
	fflag = FREAD;

	rwflag = 0;

	if (vp->v_type == VREG) {

		if (bcount == 0)
			goto out;

		/*
		 * Return EINVAL if an invalid offset comes to pread.
		 * Negative offset from user will cause this error.
		 */

		if (fileoff > maxoff) {
			error = EINVAL;
			goto out;
		}
		/*
		 * Limit offset such that we don't read or write
		 * a file beyond the maximum offset representable in
		 * an off_t structure.
		 */
		if (fileoff + bcount > maxoff)
			bcount = (ssize_t)((offset_t)maxoff - fileoff);
	} else if (vp->v_type == VFIFO) {
		error = ESPIPE;
		goto out;
	}

	aiov.iov_base = cbuf;
	aiov.iov_len = bcount;
	(void) VOP_RWLOCK(vp, rwflag, NULL);
	auio.uio_loffset = fileoff;
	auio.uio_iov = &aiov;
	auio.uio_iovcnt = 1;
	auio.uio_resid = bcount;
	auio.uio_segflg = UIO_USERSPACE;
	auio.uio_llimit = MAXOFFSET_T;
	auio.uio_fmode = fflag;
	auio.uio_extflg = UIO_COPY_CACHED;

	ioflag = auio.uio_fmode & (FAPPEND|FSYNC|FDSYNC|FRSYNC);

	/* If read sync is not asked for, filter sync flags */
	if ((ioflag & FRSYNC) == 0)
		ioflag &= ~(FSYNC|FDSYNC);
	error = VOP_READ(vp, &auio, ioflag, CRED(), NULL);
	bcount -= auio.uio_resid;
	VOP_RWUNLOCK(vp, rwflag, NULL);

	if (error == EINTR && bcount != 0)
		error = 0;
out:
	if (error)
		return (set_errno(error));
	return (bcount);
}

ssize_t
fake_pwrite(vnode_t *vp, void *cbuf, size_t count, off_t offset)
{
	struct uio auio;
	struct iovec aiov;
	int fflag, ioflag, rwflag;
	ssize_t bcount;
	int error = 0;
	u_offset_t fileoff = (u_offset_t)(ulong_t)offset;
	const u_offset_t maxoff = MAXOFF32_T;

	if ((bcount = (ssize_t)count) < 0)
		return (set_errno(EINVAL));
	fflag = FREAD | FWRITE;

	rwflag = 1;

	if (vp->v_type == VREG) {

		if (bcount == 0)
			goto out;

		/*
		 * return EINVAL for offsets that cannot be
		 * represented in an off_t.
		 */
		if (fileoff > maxoff) {
			error = EINVAL;
			goto out;
		}
		/*
		 * Don't allow pwrite to cause file sizes to exceed
		 * maxoff.
		 */
		if (fileoff == maxoff) {
			error = EFBIG;
			goto out;
		}
		if (fileoff + count > maxoff)
			bcount = (ssize_t)((u_offset_t)maxoff - fileoff);
	} else if (vp->v_type == VFIFO) {
		error = ESPIPE;
		goto out;
	}

	aiov.iov_base = cbuf;
	aiov.iov_len = bcount;
	(void) VOP_RWLOCK(vp, rwflag, NULL);
	auio.uio_loffset = fileoff;
	auio.uio_iov = &aiov;
	auio.uio_iovcnt = 1;
	auio.uio_resid = bcount;
	auio.uio_segflg = UIO_USERSPACE;
	auio.uio_llimit = MAXOFFSET_T;
	auio.uio_fmode = fflag;
	auio.uio_extflg = UIO_COPY_CACHED;

	/*
	 * The SUSv4 POSIX specification states:
	 *	The pwrite() function shall be equivalent to write(), except
	 *	that it writes into a given position and does not change
	 *	the file offset (regardless of whether O_APPEND is set).
	 * To make this be true, we omit the FAPPEND flag from ioflag.
	 */
	ioflag = auio.uio_fmode & (FSYNC|FDSYNC|FRSYNC);

	error = VOP_WRITE(vp, &auio, ioflag, CRED(), NULL);
	bcount -= auio.uio_resid;
	VOP_RWUNLOCK(vp, rwflag, NULL);

	if (error == EINTR && bcount != 0)
		error = 0;
out:
	if (error)
		return (set_errno(error));
	return (bcount);
}
