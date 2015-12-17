/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2015 Joyent, Inc.
 */

#include <sys/systm.h>
#include <sys/types.h>
#include <sys/errno.h>
#include <sys/file.h>
#include <sys/vfs.h>
#include <sys/vnode.h>
#include <sys/lx_impl.h>
#include <sys/lx_brand.h>

long
lx_syncfs(int fd)
{
	file_t *fp;
	vfs_t *vfsp;

	if ((fp = getf(fd)) == NULL)
		return (set_errno(EBADF));

	vfsp = fp->f_vnode->v_vfsp;
	releasef(fd);

	(void) (vfsp->vfs_op->vfs_sync)(vfsp, 0, CRED());

	return (0);
}

#define	LX_SYNC_FILE_RANGE_WAIT_BEFORE	0x1
#define	LX_SYNC_FILE_RANGE_WRITE	0x2
#define	LX_SYNC_FILE_RANGE_WAIT_AFTER	0x4

#define	LX_SYNC_FILE_RANGE_VALID	(LX_SYNC_FILE_RANGE_WAIT_BEFORE | \
	LX_SYNC_FILE_RANGE_WRITE | LX_SYNC_FILE_RANGE_WAIT_AFTER)


long
lx_sync_file_range(int fd, off_t offset, off_t nbytes, int flags)
{
	file_t *fp;
	int error, sflags = 0;

	if ((flags & ~LX_SYNC_FILE_RANGE_VALID) != 0)
		return (set_errno(EINVAL));
	if (offset < 0 || nbytes < 0)
		return (set_errno(EINVAL));

	if ((fp = getf(fd)) == NULL)
		return (set_errno(EBADF));

	/*
	 * Since sync_file_range is implemented in terms of VOP_PUTPAGE, both
	 * SYNC_FILE_RANGE_WAIT flags are treated as forcing synchronous
	 * operation.  While this differs from the Linux behavior where
	 * BEFORE/AFTER are distinct, it achieves an adequate level of safety
	 * since the requested data is synced out at the end of the call.
	 */
	if ((flags & (LX_SYNC_FILE_RANGE_WAIT_BEFORE |
	    LX_SYNC_FILE_RANGE_WAIT_AFTER)) == 0) {
		sflags |= B_ASYNC;
	}

	error = VOP_PUTPAGE(fp->f_vnode, offset, nbytes, sflags, CRED(), NULL);
	if (error == ENOSYS) {
		error = ESPIPE;
	}

	releasef(fd);
	if (error != 0) {
		return (set_errno(error));
	}
	return (0);
}
