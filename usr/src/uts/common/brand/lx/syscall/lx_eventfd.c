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
 * Copyright 2017 Joyent, Inc.
 */

#include <sys/types.h>
#include <sys/systm.h>
#include <sys/fcntl.h>
#include <sys/file.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/sunldi.h>
#include <sys/vnode.h>
#include <sys/eventfd.h>

static major_t eventfd_major = 0;

/* io_submit uses this to validate control block eventfd descriptors */
boolean_t
lx_is_eventfd(file_t *fp)
{
	vnode_t *vp = fp->f_vnode;

	if (vp->v_type == VCHR && getmajor(vp->v_rdev) == eventfd_major)
		return (B_TRUE);
	return (B_FALSE);
}

long
lx_eventfd2(uint_t initval, int flags)
{
	int err, fd;
	int fmode = FREAD | FWRITE;
	vnode_t *vp = NULL;
	file_t *fp = NULL;

	if (flags & ~(EFD_NONBLOCK | EFD_CLOEXEC | EFD_SEMAPHORE))
		return (set_errno(EINVAL));

	if (flags & EFD_NONBLOCK)
		fmode |= FNONBLOCK;

	if (falloc((vnode_t *)NULL, fmode, &fp, &fd) != 0)
		return (set_errno(EMFILE));

	if (ldi_vp_from_name("/dev/eventfd", &vp) != 0) {
		/*
		 * If /dev/eventfd is not available then it is less jarring to
		 * Linux programs to tell them that the system call is not
		 * supported instead of reporting an error (ENOENT) they are
		 * not expecting.
		 */
		err = ENOTSUP;
		goto error;
	}
	if ((err = VOP_OPEN(&vp, fmode | FKLYR, CRED(), NULL)) != 0) {
		VN_RELE(vp);
		vp = NULL;
		goto error;
	}

	if (flags & EFD_SEMAPHORE) {
		int rv;

		if ((err = VOP_IOCTL(vp, EVENTFDIOC_SEMAPHORE, 0, fmode, CRED(),
		    &rv, NULL)) != 0)
			goto error;
	}

	if (initval != 0) {
		uint64_t val = initval;
		struct uio auio;
		struct iovec aiov;

		/* write initial value */
		aiov.iov_base = (caddr_t)&val;
		aiov.iov_len = sizeof (val);
		auio.uio_iov = &aiov;
		auio.uio_iovcnt = 1;
		auio.uio_loffset = 0;
		auio.uio_offset = 0;
		auio.uio_resid = sizeof (val);
		auio.uio_segflg = UIO_SYSSPACE;
		auio.uio_fmode = FWRITE;

		if ((err = VOP_WRITE(vp, &auio, FWRITE, CRED(), NULL)) != 0)
			goto error;
	}

	eventfd_major = getmajor(vp->v_rdev);

	fp->f_vnode = vp;
	mutex_exit(&fp->f_tlock);
	setf(fd, fp);
	if (flags & EFD_CLOEXEC) {
		f_setfd(fd, FD_CLOEXEC);
	}
	return (fd);

error:
	if (fp != NULL) {
		setf(fd, NULL);
		unfalloc(fp);
	}
	if (vp != NULL) {
		(void) VOP_CLOSE(vp, fmode, 0, 0, CRED(), NULL);
		VN_RELE(vp);
	}
	return (set_errno(err));
}

long
lx_eventfd(uint_t val)
{
	return (lx_eventfd2(val, 0));
}
