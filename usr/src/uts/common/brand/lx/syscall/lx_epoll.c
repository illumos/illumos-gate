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
 * Copyright 2016 Joyent, Inc.
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
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/sunldi.h>
#include <sys/vnode.h>
#include <sys/lx_brand.h>
#include <sys/lx_types.h>
#include <sys/lx_signal.h>

static major_t devpoll_major = 0;

static boolean_t
lx_epoll_isvalid(file_t *fp)
{
	vnode_t *vp = fp->f_vnode;

	if (vp->v_type == VCHR && getmajor(vp->v_rdev) == devpoll_major)
		return (B_TRUE);
	return (B_FALSE);
}

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

	devpoll_major = getmajor(vp->v_rdev);

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


/* Match values from libc implementation */
#define	EPOLLIGNORED 	(EPOLLMSG | EPOLLWAKEUP)
#define	EPOLLSWIZZLED	\
	(EPOLLRDHUP | EPOLLONESHOT | EPOLLET | EPOLLWRBAND | EPOLLWRNORM)

long
lx_epoll_ctl(int fd, int op, int pfd, void *event)
{
	epoll_event_t epevent;
	dvpoll_epollfd_t dpevent[2];
	file_t *fp;
	iovec_t aiov;
	uio_t auio;
	uint32_t events, ev = 0;
	int error = 0, i = 0;

	dpevent[i].dpep_pollfd.fd = pfd;
	switch (op) {
	case EPOLL_CTL_DEL:
		dpevent[i].dpep_pollfd.events = POLLREMOVE;
		break;

	case EPOLL_CTL_MOD:
		/*
		 * In the modify case, we pass down two events:  one to
		 * remove the event and another to add it back.
		 */
		dpevent[i++].dpep_pollfd.events = POLLREMOVE;
		dpevent[i].dpep_pollfd.fd = pfd;
		/* FALLTHROUGH */

	case EPOLL_CTL_ADD:
		if (copyin(event, &epevent, sizeof (epevent)) != 0)
			return (set_errno(EFAULT));

		/*
		 * Mask off the events that we ignore, and then swizzle the
		 * events for which our values differ from their epoll(7)
		 * equivalents.
		 */
		events = epevent.events;
		ev = events & ~(EPOLLIGNORED | EPOLLSWIZZLED);

		if (events & EPOLLRDHUP)
			ev |= POLLRDHUP;
		if (events & EPOLLET)
			ev |= POLLET;
		if (events & EPOLLONESHOT)
			ev |= POLLONESHOT;
		if (events & EPOLLWRNORM)
			ev |= POLLWRNORM;
		if (events & EPOLLWRBAND)
			ev |= POLLWRBAND;

		dpevent[i].dpep_data = epevent.data.u64;
		dpevent[i].dpep_pollfd.events = ev;
		break;

	default:
		return (set_errno(EINVAL));
	}

	if ((fp = getf(fd)) == NULL) {
		return (set_errno(EBADF));
	} else if (!lx_epoll_isvalid(fp)) {
		releasef(fd);
		return (set_errno(EINVAL));
	}

	aiov.iov_base = (void *)dpevent;
	aiov.iov_len = sizeof (dvpoll_epollfd_t) * (i + 1);
	auio.uio_iov = &aiov;
	auio.uio_iovcnt = 1;
	auio.uio_resid = aiov.iov_len;
	auio.uio_segflg = UIO_SYSSPACE;
	auio.uio_loffset = 0;
	auio.uio_fmode = fp->f_flag;

	error = VOP_WRITE(fp->f_vnode, &auio, 1, fp->f_cred, NULL);

	releasef(fd);
	if (error == ELOOP) {
		/*
		 * In the case of descriptor loops, /dev/poll emits a more
		 * descriptive error than Linux epoll consumers would expect.
		 */
		return (set_errno(EINVAL));
	} else if (error != 0) {
		return (set_errno(error));
	}
	return (0);
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
	} else if (!lx_epoll_isvalid(fp)) {
		releasef(fd);
		return (set_errno(EINVAL));
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
	k_sigset_t ksig;

	if (maxevents <= 0) {
		return (set_errno(EINVAL));
	}
	if ((fp = getf(fd)) == NULL) {
		return (set_errno(EBADF));
	} else if (!lx_epoll_isvalid(fp)) {
		releasef(fd);
		return (set_errno(EINVAL));
	}
	if (sigmask != NULL) {
		lx_sigset_t lsig;

		if (copyin(sigmask, &lsig, sizeof (lsig)) != 0) {
			releasef(fd);
			return (set_errno(EFAULT));
		}
		lx_ltos_sigset(&lsig, &ksig);
		arg.dp_setp = (sigset_t *)&ksig;
	} else {
		arg.dp_setp = NULL;
	}

	arg.dp_nfds = maxevents;
	arg.dp_timeout = timeout;
	arg.dp_fds = (pollfd_t *)events;
	flag = fp->f_flag | DATAMODEL_NATIVE | FKIOCTL;
	error = VOP_IOCTL(fp->f_vnode, DP_PPOLL, (uintptr_t)&arg, flag,
	    fp->f_cred, &rv, NULL);

	releasef(fd);
	if (error != 0) {
		return (set_errno(error));
	}
	return (rv);
}
