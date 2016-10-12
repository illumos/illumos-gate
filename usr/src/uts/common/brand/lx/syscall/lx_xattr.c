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

#include <sys/errno.h>
#include <sys/systm.h>
#include <sys/file.h>
#include <sys/vnode.h>
#include <sys/pathname.h>


#define	LX_XATTR_NAME_MAX	255
#define	LX_XATTR_SIZE_MAX	65536
#define	LX_XATTR_LIST_MAX	65536

#define	LX_XATTR_FLAG_CREATE	0x1
#define	LX_XATTR_FLAG_REPLACE	0x2
#define	LX_XATTR_FLAGS_VALID	(LX_XATTR_FLAG_CREATE | LX_XATTR_FLAG_REPLACE)

#define	LX_CAP_XATTR_NAME	"security.capability"

/*
 * *xattr() family of functions.
 *
 * These are largely unimplemented.  In most cases we return EOPNOTSUPP, rather
 * than using NOSYS_NO_EQUIV to avoid unwanted stderr output from ls(1).
 *
 * Note that CRED() is used instead of f_cred in the f*xattr functions.  This
 * is intentional as Linux does not have the same notion of per-fd credentials.
 */

/* ARGSUSED */
static int
lx_setxattr_common(vnode_t *vp, char *name, void *value, size_t size,
    int flags)
{
	int error;
	char name_buf[LX_XATTR_NAME_MAX + 1];
	size_t name_len;

	if ((flags & ~LX_XATTR_FLAGS_VALID) != 0) {
		return (EINVAL);
	}
	error = copyinstr(name, name_buf, sizeof (name_buf), &name_len);
	if (error == ENAMETOOLONG || name_len == sizeof (name_buf)) {
		return (ERANGE);
	} else if (error != 0) {
		return (EFAULT);
	}
	if (size > LX_XATTR_SIZE_MAX) {
		return (E2BIG);
	}

	/*
	 * In order to keep package management software happy, despite lacking
	 * support for file-based Linux capabilities via xattrs, we fake
	 * success when root attempts a setxattr on that attribute.
	 */
	if (crgetuid(CRED()) == 0 &&
	    strcmp(name_buf, LX_CAP_XATTR_NAME) == 0) {
		return (0);
	}


	return (EOPNOTSUPP);
}

/* ARGSUSED */
static int
lx_getxattr_common(vnode_t *vp, char *name, char *value, size_t size,
    ssize_t *osize)
{
	int error;
	char name_buf[LX_XATTR_NAME_MAX + 1];
	size_t name_len;

	error = copyinstr(name, name_buf, sizeof (name_buf), &name_len);
	if (error == ENAMETOOLONG || name_len == sizeof (name_buf)) {
		return (ERANGE);
	} else if (error != 0) {
		return (EFAULT);
	}

	/*
	 * Only parameter validation is attempted for now.
	 */
	return (EOPNOTSUPP);
}

/* ARGSUSED */
static int
lx_listxattr_common(vnode_t *vp, char *list, size_t size, ssize_t *osize)
{
	return (EOPNOTSUPP);
}

/* ARGSUSED */
static int
lx_removexattr_common(vnode_t *vp, char *name)
{
	int error;
	char name_buf[LX_XATTR_NAME_MAX + 1];
	size_t name_len;

	error = copyinstr(name, name_buf, sizeof (name_buf), &name_len);
	if (error == ENAMETOOLONG || name_len == sizeof (name_buf)) {
		return (ERANGE);
	} else if (error != 0) {
		return (EFAULT);
	}

	/*
	 * Only parameter validation is attempted for now.
	 */
	return (EOPNOTSUPP);
}


long
lx_setxattr(char *path, char *name, void *value, size_t size, int flags)
{
	int error;
	vnode_t *vp = NULL;

	error = lookupname(path, UIO_USERSPACE, FOLLOW, NULLVPP, &vp);
	if (error != 0) {
		return (set_errno(error));
	}

	error = lx_setxattr_common(vp, name, value, size, flags);
	VN_RELE(vp);

	if (error != 0) {
		return (set_errno(error));
	}
	return (0);
}

long
lx_lsetxattr(char *path, char *name, void *value, size_t size, int flags)
{
	int error;
	vnode_t *vp = NULL;

	error = lookupname(path, UIO_USERSPACE, NO_FOLLOW, NULLVPP, &vp);
	if (error != 0) {
		return (set_errno(error));
	}

	error = lx_setxattr_common(vp, name, value, size, flags);
	VN_RELE(vp);

	if (error != 0) {
		return (set_errno(error));
	}
	return (0);
}

long
lx_fsetxattr(int fd, char *name, void *value, size_t size, int flags)
{
	int error;
	file_t *fp;

	if ((fp = getf(fd)) == NULL) {
		return (set_errno(EBADF));
	}

	error = lx_setxattr_common(fp->f_vnode, name, value, size, flags);
	releasef(fd);

	if (error != 0) {
		return (set_errno(error));
	}
	return (0);
}

ssize_t
lx_getxattr(char *path, char *name, void *value, size_t size)
{
	int error;
	vnode_t *vp = NULL;
	ssize_t osize;

	error = lookupname(path, UIO_USERSPACE, FOLLOW, NULLVPP, &vp);
	if (error != 0) {
		return (set_errno(error));
	}

	error = lx_getxattr_common(vp, name, value, size, &osize);
	VN_RELE(vp);

	if (error != 0) {
		return (set_errno(error));
	}
	return (osize);
}

ssize_t
lx_lgetxattr(char *path, char *name, void *value, size_t size)
{

	int error;
	vnode_t *vp = NULL;
	ssize_t osize;

	error = lookupname(path, UIO_USERSPACE, NO_FOLLOW, NULLVPP, &vp);
	if (error != 0) {
		return (set_errno(error));
	}

	error = lx_getxattr_common(vp, name, value, size, &osize);
	VN_RELE(vp);

	if (error != 0) {
		return (set_errno(error));
	}
	return (osize);
}

ssize_t
lx_fgetxattr(int fd, char *name, void *value, size_t size)
{
	int error;
	file_t *fp;
	ssize_t osize;

	if ((fp = getf(fd)) == NULL) {
		return (set_errno(EBADF));
	}

	/*
	 * When a file is opened with O_PATH we clear read/write and fgetxattr
	 * is expected to return EBADF.
	 */
	if ((fp->f_flag & (FREAD | FWRITE)) == 0) {
		releasef(fd);
		return (set_errno(EBADF));
	}

	error = lx_getxattr_common(fp->f_vnode, name, value, size, &osize);
	releasef(fd);

	if (error != 0) {
		return (set_errno(error));
	}
	return (osize);
}

ssize_t
lx_listxattr(char *path, char *list, size_t size)
{
	int error;
	vnode_t *vp = NULL;
	ssize_t osize;

	error = lookupname(path, UIO_USERSPACE, FOLLOW, NULLVPP, &vp);
	if (error != 0) {
		return (set_errno(error));
	}

	error = lx_listxattr_common(vp, list, size, &osize);
	VN_RELE(vp);

	if (error != 0) {
		return (set_errno(error));
	}
	return (osize);
}

ssize_t
lx_llistxattr(char *path, char *list, size_t size)
{
	int error;
	vnode_t *vp = NULL;
	ssize_t osize;

	error = lookupname(path, UIO_USERSPACE, NO_FOLLOW, NULLVPP, &vp);
	if (error != 0) {
		return (set_errno(error));
	}

	error = lx_listxattr_common(vp, list, size, &osize);
	VN_RELE(vp);

	if (error != 0) {
		return (set_errno(error));
	}
	return (osize);
}

ssize_t
lx_flistxattr(int fd, char *list, size_t size)
{
	int error;
	file_t *fp;
	ssize_t osize;

	if ((fp = getf(fd)) == NULL) {
		return (set_errno(EBADF));
	}

	error = lx_listxattr_common(fp->f_vnode, list, size, &osize);
	releasef(fd);

	if (error != 0) {
		return (set_errno(error));
	}
	return (osize);
}

int
lx_removexattr(char *path, char *name)
{
	int error;
	vnode_t *vp = NULL;

	error = lookupname(path, UIO_USERSPACE, FOLLOW, NULLVPP, &vp);
	if (error != 0) {
		return (set_errno(error));
	}

	error = lx_removexattr_common(vp, name);
	VN_RELE(vp);

	if (error != 0) {
		return (set_errno(error));
	}
	return (0);
}

int
lx_lremovexattr(char *path, char *name)
{
	int error;
	vnode_t *vp = NULL;

	error = lookupname(path, UIO_USERSPACE, NO_FOLLOW, NULLVPP, &vp);
	if (error != 0) {
		return (set_errno(error));
	}

	error = lx_removexattr_common(vp, name);
	VN_RELE(vp);

	if (error != 0) {
		return (set_errno(error));
	}
	return (0);
}

int
lx_fremovexattr(int fd, char *name)
{
	int error;
	file_t *fp;

	if ((fp = getf(fd)) == NULL) {
		return (set_errno(EBADF));
	}

	error = lx_removexattr_common(fp->f_vnode, name);
	releasef(fd);

	if (error != 0) {
		return (set_errno(error));
	}
	return (0);
}
