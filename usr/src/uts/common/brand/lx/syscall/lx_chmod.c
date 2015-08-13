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
#include <sys/fcntl.h>
#include <sys/thread.h>
#include <sys/klwp.h>
#include <sys/lx_brand.h>
#include <sys/lx_fcntl.h>

long
lx_vn_chmod(vnode_t *vp, int mode)
{
	vattr_t vattr;

	vattr.va_mode = mode & MODEMASK;
	vattr.va_mask = AT_MODE;

	if (vn_is_readonly(vp)) {
		return (EROFS);
	}
	return (VOP_SETATTR(vp, &vattr, 0, CRED(), NULL));
}

static long
lx_fchmodat_wrapper(int fd, char *path, int mode)
{
	long error;
	vnode_t *vp;

	if ((error = lx_vp_at(fd, path, &vp, 0)) != 0) {
		lx_proc_data_t *pd = ttolxproc(curthread);

		/*
		 * If the process is in "install mode", return success
		 * if the operation failed due to an absent file.
		 */
		if (error == ENOENT &&
		    (pd->l_flags & LX_PROC_INSTALL_MODE)) {
			return (0);
		}
		return (set_errno(error));
	}

	error = lx_vn_chmod(vp, mode);
	VN_RELE(vp);

	if (error != 0) {
		return (set_errno(error));
	}
	return (0);
}

long
lx_fchmodat(int fd, char *path, int mode)
{
	return (lx_fchmodat_wrapper(fd, path, mode));
}

long
lx_fchmod(int fd, int mode)
{
	file_t *fp;
	vnode_t *vp;
	long error;

	/*
	 * In order to do proper O_PATH handling, lx_fchmod cannot leverage
	 * lx_fchmodat with a NULL path since the desired behavior differs.
	 */
	if ((fp = getf(fd)) == NULL) {
		return (set_errno(EBADF));
	}
	if (LX_IS_O_PATH(fp)) {
		releasef(fd);
		return (set_errno(EBADF));
	}
	vp = fp->f_vnode;
	VN_HOLD(vp);
	releasef(fd);

	error = lx_vn_chmod(vp, mode);
	VN_RELE(vp);

	if (error != 0) {
		return (set_errno(error));
	}
	return (0);
}

long
lx_chmod(char *path, int mode)
{
	return (lx_fchmodat_wrapper(LX_AT_FDCWD, path, mode));
}
