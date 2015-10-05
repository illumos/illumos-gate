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

#include <sys/types.h>
#include <sys/systm.h>
#include <sys/thread.h>
#include <sys/proc.h>
#include <sys/zone.h>
#include <sys/brand.h>
#include <sys/epoll.h>
#include <sys/devpoll.h>
#include <sys/fcntl.h>
#include <sys/file.h>
#include <sys/sunddi.h>
#include <sys/sunldi.h>
#include <sys/vnode.h>
#include <sys/lx_brand.h>
#include <sys/lx_types.h>

long
lx_epoll_create1(int flags)
{
	int err, fd, rv;
	int fmode = FREAD | FWRITE;
	boolean_t cloexec = B_FALSE;
	vnode_t *vp = NULL;
	file_t *fp = NULL;

	if (flags & EPOLL_CLOEXEC) {
		cloexec = B_TRUE;
		flags &= ~EPOLL_CLOEXEC;
	}
	if (flags != 0) {
		/* No other flags accepted at this time */
		return (set_errno(EINVAL));
	}

	if (falloc((vnode_t *)NULL, fmode, &fp, &fd) != 0) {
		err = EMFILE;
		goto error;
	}
	if (ldi_vp_from_name("/devices/pseudo/poll@0:poll", &vp) != 0) {
		err = ENOENT;
		goto error;
	}
	if ((err = VOP_OPEN(&vp, fmode | FKLYR, CRED(), NULL)) != 0) {
		goto error;
	}
	err = VOP_IOCTL(vp, DP_EPOLLCOMPAT, 0, fmode, CRED(), &rv, NULL);
	if (err != 0) {
		(void) VOP_CLOSE(vp, fmode, 0, 0, CRED(), NULL);
		goto error;
	}

	fp->f_vnode = vp;
	mutex_exit(&fp->f_tlock);
	setf(fd, fp);
	if (cloexec) {
		f_setfd(fd, FD_CLOEXEC);
	}
	return (fd);

error:
	if (fp != NULL) {
		setf(fd, NULL);
		unfalloc(fp);
	}
	if (vp != NULL) {
		VN_RELE(vp);
	}
	return (set_errno(err));
}

long
lx_epoll_create(int size)
{
	if (size <= 0) {
		return (set_errno(EINVAL));
	}

	return (lx_epoll_create1(0));
}

long
lx_epoll_wait(int fd, void *events, int maxevents, int timeout)
{
	struct dvpoll arg;
	file_t *fp;
	int rv = 0, error, flag;

	if (maxevents <= 0) {
		return (set_errno(EINVAL));
	}
	if ((fp = getf(fd)) == NULL) {
		return (set_errno(EBADF));
	}

	arg.dp_nfds = maxevents;
	arg.dp_timeout = timeout;
	arg.dp_fds = (pollfd_t *)events;
	flag = fp->f_flag | DATAMODEL_NATIVE | FKIOCTL;
	error = VOP_IOCTL(fp->f_vnode, DP_POLL, (uintptr_t)&arg, flag,
	    fp->f_cred, &rv, NULL);

	releasef(fd);
	if (error != 0) {
		return (set_errno(error));
	}
	return (rv);
}

long
lx_epoll_pwait(int fd, void *events, int maxevents, int timeout, void *sigmask)
{
	struct dvpoll arg;
	file_t *fp;
	int rv = 0, error, flag;

	if (maxevents <= 0) {
		return (set_errno(EINVAL));
	}
	if ((fp = getf(fd)) == NULL) {
		return (set_errno(EBADF));
	}

	arg.dp_nfds = maxevents;
	arg.dp_timeout = timeout;
	arg.dp_fds = (pollfd_t *)events;
	arg.dp_setp = (sigset_t *)sigmask;
	flag = fp->f_flag | DATAMODEL_NATIVE | FKIOCTL;
	error = VOP_IOCTL(fp->f_vnode, DP_PPOLL, (uintptr_t)&arg, flag,
	    fp->f_cred, &rv, NULL);

	releasef(fd);
	if (error != 0) {
		return (set_errno(error));
	}
	return (rv);
}
