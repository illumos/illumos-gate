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
#include <sys/zone.h>
#include <sys/lx_brand.h>
#include <sys/lx_fcntl.h>
#include <sys/lx_types.h>

long
lx_vn_chown(vnode_t *vp, uid_t uid, gid_t gid)
{
	vattr_t vattr;
	zone_t *zone = crgetzone(CRED());

	if ((uid != (uid_t)-1 && !VALID_UID(uid, zone)) ||
	    (gid != (gid_t)-1 && !VALID_GID(gid, zone))) {
		return (EINVAL);
	}
	vattr.va_uid = uid;
	vattr.va_gid = gid;
	vattr.va_mask = 0;
	if (vattr.va_uid != -1)
		vattr.va_mask |= AT_UID;
	if (vattr.va_gid != -1)
		vattr.va_mask |= AT_GID;

	if (vn_is_readonly(vp)) {
		return (EROFS);
	}
	return (VOP_SETATTR(vp, &vattr, 0, CRED(), NULL));
}

long
lx_fchownat_wrapper(int fd, char *path, uid_t uid, gid_t gid, int native_flag)
{
	long error;
	vnode_t *vp;

	if ((error = lx_vp_at(fd, path, &vp, native_flag)) != 0) {
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

	error = lx_vn_chown(vp, uid, gid);
	VN_RELE(vp);

	if (error != 0) {
		return (set_errno(error));
	}
	return (0);
}

long
lx_fchown_wrapper(int fd, uid_t uid, gid_t gid)
{
	file_t *fp;
	vnode_t *vp;
	long error;

	/*
	 * In order to do proper O_PATH handling, lx_fchown cannot leverage
	 * lx_fchownat with a NULL path since the desired behavior differs.
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

	error = lx_vn_chown(vp, uid, gid);
	VN_RELE(vp);

	if (error != 0) {
		return (set_errno(error));
	}
	return (0);
}

long
lx_fchownat(int fd, char *path, uid_t uid, gid_t gid, int flag)
{
	int native_flag = 0;

	if (flag & LX_AT_EMPTY_PATH) {
		char c;

		/*
		 * According to fchownat(2), when AT_EMPTY_PATH is set: "if
		 * path is an empty string, operate on the file referred to by
		 * fd".  We pass NULL in place of the empty string, which
		 * causes fchownat() to operate on the fd we passed without an
		 * additional lookup.
		 */
		if (copyin(path, &c, sizeof (c)) != 0) {
			return (set_errno(EFAULT));
		}
		if (c == '\0') {
			path = NULL;
		}

		flag &= ~LX_AT_EMPTY_PATH;
	}
	if (flag & LX_AT_SYMLINK_NOFOLLOW) {
		flag &= ~LX_AT_SYMLINK_NOFOLLOW;
		native_flag |= AT_SYMLINK_NOFOLLOW;
	}
	if (flag != 0) {
		return (set_errno(EINVAL));
	}

	return (lx_fchownat_wrapper(fd, path, uid, gid, native_flag));
}

long
lx_fchown(int fd, uid_t uid, gid_t gid)
{
	return (lx_fchown_wrapper(fd, uid, gid));
}

long
lx_lchown(char *path, uid_t uid, gid_t gid)
{
	return (lx_fchownat_wrapper(AT_FDCWD, path, uid, gid,
	    AT_SYMLINK_NOFOLLOW));
}

long
lx_chown(char *path, uid_t uid, gid_t gid)
{
	return (lx_fchownat_wrapper(AT_FDCWD, path, uid, gid, 0));
}

long
lx_fchown16(int fd, lx_uid16_t uid, lx_gid16_t gid)
{
	return (lx_fchown_wrapper(fd, LX_UID16_TO_UID32(uid),
	    LX_GID16_TO_GID32(gid)));
}

long
lx_lchown16(char *path, uid_t uid, gid_t gid)
{
	return (lx_fchownat_wrapper(AT_FDCWD, path, LX_UID16_TO_UID32(uid),
	    LX_GID16_TO_GID32(gid), AT_SYMLINK_NOFOLLOW));
}

long
lx_chown16(char *path, lx_uid16_t uid, lx_gid16_t gid)
{
	return (lx_fchownat_wrapper(AT_FDCWD, path, LX_UID16_TO_UID32(uid),
	    LX_GID16_TO_GID32(gid), 0));
}
