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
#include <sys/lx_brand.h>
#include <sys/lx_fcntl.h>
#include <sys/lx_types.h>

/*
 * From "uts/common/syscall/chown.c":
 */
extern int fchownat(int, char *, uid_t, gid_t, int);

long
lx_fchownat_wrapper(int fd, char *path, uid_t uid, gid_t gid, int native_flag)
{
	long rval;

	if (fd == LX_AT_FDCWD) {
		fd = AT_FDCWD;
	}

	if ((rval = fchownat(fd, path, uid, gid, native_flag)) != 0) {
		lx_proc_data_t *pd = ttolxproc(curthread);
		klwp_t *lwp = ttolwp(curthread);

		/*
		 * If the process is in "install mode", return success
		 * if the operation failed due to an absent file.
		 */
		if ((pd->l_flags & LX_PROC_INSTALL_MODE) &&
		    lwp->lwp_errno == ENOENT) {
			lwp->lwp_errno = 0;
			return (0);
		}
	}

	return (rval);
}

long
lx_fchownat(int fd, char *path, uid_t uid, gid_t gid, int flag)
{
	char c;
	int native_flag = 0;

	if (copyin(path, &c, sizeof (c)) != 0) {
		return (set_errno(EFAULT));
	}

	if (flag & LX_AT_EMPTY_PATH) {
		/*
		 * According to fchownat(2), when AT_EMPTY_PATH is set: "if
		 * path is an empty string, operate on the file referred to by
		 * fd".  We pass NULL in place of the empty string, which
		 * causes fchownat() to operate on the fd we passed without an
		 * additional lookup.
		 */
		if (c == '\0') {
			path = NULL;
		}

		flag &= ~LX_AT_EMPTY_PATH;
	} else {
		/*
		 * Otherwise, a file with no filename obviously cannot be
		 * present in the directory.
		 */
		if (c == '\0') {
			return (set_errno(ENOENT));
		}
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
	return (lx_fchownat_wrapper(fd, NULL, uid, gid, 0));
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
	return (lx_fchownat_wrapper(fd, NULL, LX_UID16_TO_UID32(uid),
	    LX_GID16_TO_GID32(gid), 0));
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
