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
 * Copyright (c) 2017 Joyent, Inc.
 */

#include <sys/errno.h>
#include <sys/systm.h>
#include <sys/file.h>
#include <sys/vnode.h>
#include <sys/pathname.h>
#include <sys/lx_acl.h>


#define	LX_XATTR_NAME_MAX	255
#define	LX_XATTR_SIZE_MAX	65536
#define	LX_XATTR_LIST_MAX	65536

#define	LX_XATTR_FLAG_CREATE	0x1
#define	LX_XATTR_FLAG_REPLACE	0x2
#define	LX_XATTR_FLAGS_VALID	(LX_XATTR_FLAG_CREATE | LX_XATTR_FLAG_REPLACE)

enum lx_xattr_ns {
	LX_XATTR_NS_SECURITY,
	LX_XATTR_NS_SYSTEM,
	LX_XATTR_NS_TRUSTED,
	LX_XATTR_NS_USER,
	LX_XATTR_NS_INVALID	/* Catch-all for invalid namespaces */
};

/* Present under the 'security.' namespace */
#define	LX_XATTR_CAPABILITY	"capability"

typedef struct lx_xattr_ns_list {
	const char *lxnl_name;
	unsigned lxnl_len;
	enum lx_xattr_ns lxnl_ns;
} lx_xattr_ns_list_t;

static lx_xattr_ns_list_t lx_xattr_namespaces[] = {
	{ "user.", 5, LX_XATTR_NS_USER },
	{ "system.", 7, LX_XATTR_NS_SYSTEM },
	{ "trusted.", 8, LX_XATTR_NS_TRUSTED },
	{ "security.", 9, LX_XATTR_NS_SECURITY },
	{ NULL, 0, LX_XATTR_NS_INVALID }
};

static int
lx_xattr_parse(const char *name, size_t nlen, const char **key)
{
	lx_xattr_ns_list_t *lxn = lx_xattr_namespaces;

	for (; lxn->lxnl_name != NULL; lxn++) {
		if (nlen < lxn->lxnl_len) {
			continue;
		}
		if (strncmp(lxn->lxnl_name, name, lxn->lxnl_len) == 0) {
			*key = name + (lxn->lxnl_len);
			return (lxn->lxnl_ns);
		}
	}

	*key = name;
	return (LX_XATTR_NS_INVALID);
}

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
lx_setxattr_common(vnode_t *vp, char *name, void *value, size_t sz, int flags)
{
	int error, type;
	char name_buf[LX_XATTR_NAME_MAX + 1];
	const char *key;
	size_t name_len;
	void *buf = NULL;

	if ((flags & ~LX_XATTR_FLAGS_VALID) != 0) {
		return (EINVAL);
	}
	error = copyinstr(name, name_buf, sizeof (name_buf), &name_len);
	if (error == ENAMETOOLONG || name_len == sizeof (name_buf)) {
		return (ERANGE);
	} else if (error != 0) {
		return (EFAULT);
	}

	type = lx_xattr_parse(name_buf, name_len, &key);

	if (sz != 0) {
		if (sz > LX_XATTR_SIZE_MAX) {
			return (E2BIG);
		}
		buf = kmem_alloc(sz, KM_SLEEP);
		if (copyin(value, buf, sz) != 0) {
			kmem_free(buf, sz);
			return (EFAULT);
		}
	}

	error = EOPNOTSUPP;
	switch (type) {
	case LX_XATTR_NS_SECURITY:
		/*
		 * In order to keep package management software happy, despite
		 * lacking support for file-based Linux capabilities via
		 * xattrs, we fake success when root attempts a setxattr on
		 * that attribute.
		 */
		if (crgetuid(CRED()) == 0 &&
		    strcmp(key, LX_XATTR_CAPABILITY) == 0) {
			error = 0;
		}
		break;
	case LX_XATTR_NS_SYSTEM:
		if (strcmp(key, LX_XATTR_POSIX_ACL_ACCESS) == 0) {
			error = lx_acl_setxattr(vp, LX_ACL_ACCESS, value, sz);
		} else if (strcmp(key, LX_XATTR_POSIX_ACL_DEFAULT) == 0) {
			error = lx_acl_setxattr(vp, LX_ACL_DEFAULT, value, sz);
		}
	default:
		break;
	}

	if (buf != NULL) {
		kmem_free(buf, sz);
	}
	return (error);
}

/* ARGSUSED */
static int
lx_getxattr_common(vnode_t *vp, char *name, char *value, size_t sz,
    ssize_t *osz)
{
	int error, type;
	char name_buf[LX_XATTR_NAME_MAX + 1];
	const char *key;
	size_t name_len;
	void *buf = NULL;

	error = copyinstr(name, name_buf, sizeof (name_buf), &name_len);
	if (error == ENAMETOOLONG || name_len == sizeof (name_buf)) {
		return (ERANGE);
	} else if (error != 0) {
		return (EFAULT);
	}
	if (sz != 0) {
		if (sz > LX_XATTR_SIZE_MAX) {
			sz = LX_XATTR_SIZE_MAX;
		}
		buf = kmem_alloc(sz, KM_SLEEP);
	}

	type = lx_xattr_parse(name_buf, name_len, &key);

	error = EOPNOTSUPP;
	switch (type) {
	case LX_XATTR_NS_SYSTEM:
		if (strcmp(key, LX_XATTR_POSIX_ACL_ACCESS) == 0) {
			error = lx_acl_getxattr(vp, LX_ACL_ACCESS, buf, sz,
			    osz);
		} else if (strcmp(key, LX_XATTR_POSIX_ACL_DEFAULT) == 0) {
			error = lx_acl_getxattr(vp, LX_ACL_DEFAULT, buf, sz,
			    osz);
		}
		break;
	default:
		break;
	}

	if (error == 0 && buf != NULL) {
		VERIFY(*osz <= sz);

		if (copyout(buf, value, *osz) != 0) {
			error = EFAULT;
		}
	}
	if (buf != NULL) {
		kmem_free(buf, sz);
	}
	return (error);
}

/* ARGSUSED */
static int
lx_listxattr_common(vnode_t *vp, void *value, size_t size, ssize_t *osize)
{
	struct uio auio;
	struct iovec aiov;
	int err = 0;

	aiov.iov_base = value;
	aiov.iov_len = size;
	auio.uio_iov = &aiov;
	auio.uio_iovcnt = 1;
	auio.uio_loffset = 0;
	auio.uio_segflg = UIO_USERSPACE;
	auio.uio_resid = size;
	auio.uio_fmode = 0;
	auio.uio_extflg = UIO_COPY_CACHED;

	/*
	 * Call into all the listxattr routines (which may be no-ops) which are
	 * currently implemented.
	 */
	err = lx_acl_listxattr(vp, &auio);

	if (err == 0) {
		*osize = size - auio.uio_resid;
	}

	return (err);
}

/* ARGSUSED */
static int
lx_removexattr_common(vnode_t *vp, char *name)
{
	int error, type;
	char name_buf[LX_XATTR_NAME_MAX + 1];
	const char *key;
	size_t name_len;

	error = copyinstr(name, name_buf, sizeof (name_buf), &name_len);
	if (error == ENAMETOOLONG || name_len == sizeof (name_buf)) {
		return (ERANGE);
	} else if (error != 0) {
		return (EFAULT);
	}


	type = lx_xattr_parse(name_buf, name_len, &key);

	error = EOPNOTSUPP;
	switch (type) {
	case LX_XATTR_NS_SYSTEM:
		if (strcmp(key, LX_XATTR_POSIX_ACL_ACCESS) == 0) {
			error = lx_acl_removexattr(vp, LX_ACL_ACCESS);
		} else if (strcmp(key, LX_XATTR_POSIX_ACL_DEFAULT) == 0) {
			error = lx_acl_removexattr(vp, LX_ACL_DEFAULT);
		}
	default:
		break;
	}

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
