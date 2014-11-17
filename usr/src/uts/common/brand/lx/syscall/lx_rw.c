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
 * Copyright 2014 Joyent, Inc.  All rights reserved.
 */

#include <sys/errno.h>
#include <sys/systm.h>
#include <sys/file.h>
#include <sys/vnode.h>

/* uts/common/syscall/rw.c */
extern ssize_t read(int fdes, void *cbuf, size_t count);

ssize_t
lx_read(int fd, void *buf, size_t nbyte)
{
	file_t *fp;
	vtype_t t;

	if ((fp = getf(fd)) == NULL)
		return (set_errno(EBADF));
	t = fp->f_vnode->v_type;
	releasef(fd);

	if (t == VDIR)
		return (set_errno(EISDIR));

	return (read(fd, buf, nbyte));
}
