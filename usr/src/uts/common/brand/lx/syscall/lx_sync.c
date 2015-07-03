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
#include <sys/vfs.h>
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
