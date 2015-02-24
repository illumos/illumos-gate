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

#include <sys/errno.h>
#include <sys/systm.h>
#include <sys/file.h>
#include <sys/vnode.h>
#include <sys/brand.h>
#include <sys/lx_brand.h>

/* uts/common/syscall/rw.c */
extern ssize_t read(int fdes, void *cbuf, size_t count);
extern ssize_t write(int fdes, void *cbuf, size_t count);

long
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

	/*
	 * If read(2) returns EINTR, we want to signal that restarting the
	 * system call is acceptable:
	 */
	ttolxlwp(curthread)->br_syscall_restart = B_TRUE;

	return (read(fd, buf, nbyte));
}

long
lx_write(int fd, void *buf, size_t nbyte)
{
	/*
	 * If write(2) returns EINTR, we want to signal that restarting the
	 * system call is acceptable:
	 */
	ttolxlwp(curthread)->br_syscall_restart = B_TRUE;

	return (write(fd, buf, nbyte));
}
