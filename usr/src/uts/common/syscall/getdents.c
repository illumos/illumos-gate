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
#include <sys/inttypes.h>
#include <sys/sysmacros.h>
#include <sys/cred.h>
#include <sys/dirent.h>
#include <sys/systm.h>
#include <sys/errno.h>
#include <sys/vnode.h>
#include <sys/file.h>
#include <sys/mode.h>
#include <sys/uio.h>
#include <sys/filio.h>
#include <sys/debug.h>
#include <sys/kmem.h>
#include <sys/cmn_err.h>

#if defined(_SYSCALL32_IMPL) || defined(_ILP32)

/*
 * Get directory entries in a file system-independent format.
 *
 * The 32-bit version of this function now allocates a buffer to grab the
 * directory entries in dirent64 formats from VOP_READDIR routines.
 * The dirent64 structures are converted to dirent32 structures and
 * copied to the user space.
 *
 * Both 32-bit and 64-bit versions of libc use getdents64() and therefore
 * we don't expect any major performance impact due to the extra kmem_alloc's
 * and copying done in this routine.
 */

/*
 * Native 32-bit system call for non-large-file applications.
 */
int
getdents32(int fd, void *buf, size_t count)
{
	vnode_t *vp;
	file_t *fp;
	struct uio auio;
	struct iovec aiov;
	register int error;
	int sink;
	char *newbuf;
	char *obuf;
	int bufsize;
	int osize, nsize;
	struct dirent64 *dp;
	struct dirent32 *op;

	if (count < sizeof (struct dirent32))
		return (set_errno(EINVAL));

	if ((fp = getf(fd)) == NULL)
		return (set_errno(EBADF));
	vp = fp->f_vnode;
	if (vp->v_type != VDIR) {
		releasef(fd);
		return (set_errno(ENOTDIR));
	}
	if (!(fp->f_flag & FREAD)) {
		releasef(fd);
		return (set_errno(EBADF));
	}

	/*
	 * Don't let the user overcommit kernel resources.
	 */
	if (count > MAXGETDENTS_SIZE)
		count = MAXGETDENTS_SIZE;

	bufsize = count;
	newbuf = kmem_alloc(bufsize, KM_SLEEP);
	obuf = kmem_alloc(bufsize, KM_SLEEP);

	aiov.iov_base = newbuf;
	aiov.iov_len = count;
	auio.uio_iov = &aiov;
	auio.uio_iovcnt = 1;
	auio.uio_loffset = fp->f_offset;
	auio.uio_segflg = UIO_SYSSPACE;
	auio.uio_resid = count;
	auio.uio_fmode = 0;
	auio.uio_extflg = UIO_COPY_CACHED;
	(void) VOP_RWLOCK(vp, V_WRITELOCK_FALSE, NULL);
	error = VOP_READDIR(vp, &auio, fp->f_cred, &sink, NULL, 0);
	VOP_RWUNLOCK(vp, V_WRITELOCK_FALSE, NULL);
	if (error)
		goto out;
	count = count - auio.uio_resid;
	fp->f_offset = auio.uio_loffset;

	dp = (struct dirent64 *)newbuf;
	op = (struct dirent32 *)obuf;
	osize = 0;
	nsize = 0;

	while (nsize < count) {
		uint32_t reclen, namlen;

		/*
		 * This check ensures that the 64 bit d_ino and d_off
		 * fields will fit into their 32 bit equivalents.
		 *
		 * Although d_off is a signed value, the check is done
		 * against the full 32 bits because certain file systems,
		 * NFS for one, allow directory cookies to use the full
		 * 32 bits.  We use uint64_t because there is no exact
		 * unsigned analog to the off64_t type of dp->d_off.
		 */
		if (dp->d_ino > (ino64_t)UINT32_MAX ||
		    dp->d_off > (uint64_t)UINT32_MAX) {
			error = EOVERFLOW;
			goto out;
		}
		op->d_ino = (ino32_t)dp->d_ino;
		op->d_off = (off32_t)dp->d_off;
		namlen = strlen(dp->d_name);
		reclen = DIRENT32_RECLEN(namlen);
		op->d_reclen = (uint16_t)reclen;

		/* use strncpy(9f) to zero out uninitialized bytes */

		(void) strncpy(op->d_name, dp->d_name,
		    DIRENT32_NAMELEN(reclen));
		nsize += (uint_t)dp->d_reclen;
		osize += (uint_t)op->d_reclen;
		dp = (struct dirent64 *)((char *)dp + (uint_t)dp->d_reclen);
		op = (struct dirent32 *)((char *)op + (uint_t)op->d_reclen);
	}

	ASSERT(osize <= count);
	ASSERT((char *)op <= (char *)obuf + bufsize);
	ASSERT((char *)dp <= (char *)newbuf + bufsize);

	if ((error = copyout(obuf, buf, osize)) < 0)
		error = EFAULT;
out:
	kmem_free(newbuf, bufsize);
	kmem_free(obuf, bufsize);

	if (error) {
		releasef(fd);
		return (set_errno(error));
	}

	releasef(fd);
	return (osize);
}

#endif	/* _SYSCALL32 || _ILP32 */

int
getdents64(int fd, void *buf, size_t count)
{
	vnode_t *vp;
	file_t *fp;
	struct uio auio;
	struct iovec aiov;
	register int error;
	int sink;

	if (count < sizeof (struct dirent64))
		return (set_errno(EINVAL));

	/*
	 * Don't let the user overcommit kernel resources.
	 */
	if (count > MAXGETDENTS_SIZE)
		count = MAXGETDENTS_SIZE;

	if ((fp = getf(fd)) == NULL)
		return (set_errno(EBADF));
	vp = fp->f_vnode;
	if (vp->v_type != VDIR) {
		releasef(fd);
		return (set_errno(ENOTDIR));
	}
	if (!(fp->f_flag & FREAD)) {
		releasef(fd);
		return (set_errno(EBADF));
	}
	aiov.iov_base = buf;
	aiov.iov_len = count;
	auio.uio_iov = &aiov;
	auio.uio_iovcnt = 1;
	auio.uio_loffset = fp->f_offset;
	auio.uio_segflg = UIO_USERSPACE;
	auio.uio_resid = count;
	auio.uio_fmode = 0;
	auio.uio_extflg = UIO_COPY_CACHED;
	(void) VOP_RWLOCK(vp, V_WRITELOCK_FALSE, NULL);
	error = VOP_READDIR(vp, &auio, fp->f_cred, &sink, NULL, 0);
	VOP_RWUNLOCK(vp, V_WRITELOCK_FALSE, NULL);
	if (error) {
		releasef(fd);
		return (set_errno(error));
	}
	count = count - auio.uio_resid;
	fp->f_offset = auio.uio_loffset;
	releasef(fd);
	return (count);
}
