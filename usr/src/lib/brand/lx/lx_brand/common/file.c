/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */

/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/fstyp.h>
#include <sys/fsid.h>

#include <errno.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/vnode.h>
#include <fcntl.h>
#include <string.h>
#include <utime.h>
#include <atomic.h>

#include <sys/lx_syscall.h>
#include <sys/lx_types.h>
#include <sys/lx_debug.h>
#include <sys/lx_misc.h>
#include <sys/lx_fcntl.h>

static int
install_checkpath(uintptr_t p1)
{
	int saved_errno = errno;
	char path[MAXPATHLEN];

	/*
	 * The "dev" RPM package wants to modify /dev/pts, but /dev/pts is a
	 * lofs mounted copy of /native/dev/pts, so that won't work.
	 *
	 * Instead, if we're trying to modify /dev/pts from install mode, just
	 * act as if it succeded.
	 */
	if (uucopystr((void *)p1, path, MAXPATHLEN) == -1)
		return (-errno);

	if (strcmp(path, "/dev/pts") == 0)
		return (0);

	errno = saved_errno;
	return (-errno);
}

/*
 * Convert linux LX_AT_* flags to solaris AT_* flags, while verifying allowed
 * flags have been passed. This also allows EACCESS/REMOVEDIR to be translated
 * correctly since on linux they have the same value.
 */
int
ltos_at_flag(int lflag, int allow)
{
	int sflag = 0;

	if ((lflag & LX_AT_EACCESS) && (allow & AT_EACCESS)) {
		lflag &= ~LX_AT_EACCESS;
		sflag |= AT_EACCESS;
	}

	if ((lflag & LX_AT_REMOVEDIR) && (allow & AT_REMOVEDIR)) {
		lflag &= ~LX_AT_REMOVEDIR;
		sflag |= AT_REMOVEDIR;
	}

	if ((lflag & LX_AT_SYMLINK_NOFOLLOW) && (allow & AT_SYMLINK_NOFOLLOW)) {
		lflag &= ~LX_AT_SYMLINK_NOFOLLOW;
		sflag |= AT_SYMLINK_NOFOLLOW;
	}

	/* right now solaris doesn't have a _FOLLOW flag, so use a fake one */
	if ((lflag & LX_AT_SYMLINK_FOLLOW) && (allow & LX_AT_SYMLINK_FOLLOW)) {
		lflag &= ~LX_AT_SYMLINK_FOLLOW;
		sflag |= LX_AT_SYMLINK_FOLLOW;
	}

	/* if flag is not zero than some flags did not hit the above code */
	if (lflag)
		return (-EINVAL);

	return (sflag);
}


/*
 * Miscellaneous file-related system calls.
 */

/*
 * Linux creates half-duplex unnamed pipes and Solaris creates full-duplex
 * pipes.  Thus, to get the correct semantics, our simple pipe() system
 * call actually needs to create a named pipe, do three opens, a close, and
 * an unlink.  This is woefully expensive.  If performance becomes a real
 * issue, we can implement a half-duplex pipe() in the brand module.
 */
#define	PIPENAMESZ	32 /* enough room for /tmp/.pipe.<pid>.<num> */

int
lx_pipe(uintptr_t p1)
{
	static uint32_t pipecnt = 0;
	int cnt;
	char pipename[PIPENAMESZ];
	int fds[3];
	int r = 0;

	fds[0] = -1;
	fds[1] = -1;
	fds[2] = -1;

	/*
	 * Construct a name for the named pipe: /tmp/.pipe.<pid>.<++cnt>
	 */
	cnt = atomic_inc_32_nv(&pipecnt);

	(void) snprintf(pipename, PIPENAMESZ, "/tmp/.pipe.%d.%d",
	    getpid(), cnt);

	if (mkfifo(pipename, 0600))
		return (-errno);

	/*
	 * To prevent either the read-only or write-only open from
	 * blocking, we first need to open the pipe for both reading and
	 * writing.
	 */
	if (((fds[2] = open(pipename, O_RDWR)) < 0) ||
	    ((fds[0] = open(pipename, O_RDONLY)) < 0) ||
	    ((fds[1] = open(pipename, O_WRONLY)) < 0)) {
		r = errno;
	} else {
		/*
		 * Copy the two one-way fds back to the app's address
		 * space.
		 */
		if (uucopy(fds, (void *)p1, 2 * sizeof (int)))
			r = errno;
	}

	if (fds[2] >= 0)
		(void) close(fds[2]);
	(void) unlink(pipename);

	if (r != 0) {
		if (fds[0] >= 0)
			(void) close(fds[0]);
		if (fds[1] >= 0)
			(void) close(fds[1]);
	}

	return (-r);
}

/*
 * On Linux, even root cannot create a link to a directory, so we have to
 * add an explicit check.
 */
int
lx_link(uintptr_t p1, uintptr_t p2)
{
	char *from = (char *)p1;
	char *to = (char *)p2;
	struct stat64 statbuf;

	if ((stat64(from, &statbuf) == 0) && S_ISDIR(statbuf.st_mode))
		return (-EPERM);

	return (link(from, to) ? -errno : 0);
}

/*
 * On Linux, an unlink of a directory returns EISDIR, not EPERM.
 */
int
lx_unlink(uintptr_t p)
{
	char *pathname = (char *)p;
	struct stat64 statbuf;

	if ((lstat64(pathname, &statbuf) == 0) && S_ISDIR(statbuf.st_mode))
		return (-EISDIR);

	return (unlink(pathname) ? -errno : 0);
}

int
lx_unlinkat(uintptr_t ext1, uintptr_t p1, uintptr_t p2)
{
	int atfd = (int)ext1;
	char *pathname = (char *)p1;
	int flag = (int)p2;
	struct stat64 statbuf;

	if (atfd == LX_AT_FDCWD)
		atfd = AT_FDCWD;

	flag = ltos_at_flag(flag, AT_REMOVEDIR);
	if (flag < 0)
		return (-EINVAL);

	if (!(flag & AT_REMOVEDIR)) {
		/* Behave like unlink() */
		if ((fstatat64(atfd, pathname, &statbuf, AT_SYMLINK_NOFOLLOW) ==
		    0) && S_ISDIR(statbuf.st_mode))
			return (-EISDIR);
	}

	return (unlinkat(atfd, pathname, flag) ? -errno : 0);
}

/*
 * fsync() and fdatasync() - On Solaris, these calls translate into a common
 * fsync() syscall with a different parameter, so we layer on top of the librt
 * functions instead.
 */
int
lx_fsync(uintptr_t fd)
{
	int fildes = (int)fd;
	struct stat64 statbuf;

	if ((fstat64(fildes, &statbuf) == 0) &&
	    (S_ISCHR(statbuf.st_mode) || S_ISFIFO(statbuf.st_mode)))
		return (-EINVAL);

	return (fsync((int)fd) ? -errno : 0);
}

int
lx_fdatasync(uintptr_t fd)
{
	int fildes = (int)fd;
	struct stat64 statbuf;

	if ((fstat64(fildes, &statbuf) == 0) &&
	    (S_ISCHR(statbuf.st_mode) || S_ISFIFO(statbuf.st_mode)))
		return (-EINVAL);

	return (fdatasync((int)fd) ? -errno : 0);
}

/*
 * Linux, unlike Solaris, ALWAYS resets the setuid and setgid bits on a
 * chown/fchown  regardless of whether it was done by root or not.  Therefore,
 * we must do extra work after each chown/fchown call to emulate this behavior.
 */
#define	SETUGID	(S_ISUID | S_ISGID)

/*
 * [lf]chown16() - Translate the uid/gid and pass onto the real functions.
 */
int
lx_chown16(uintptr_t p1, uintptr_t p2, uintptr_t p3)
{
	char *filename = (char *)p1;
	struct stat64 statbuf;

	if (chown(filename, LX_UID16_TO_UID32((lx_gid16_t)p2),
	    LX_GID16_TO_GID32((lx_gid16_t)p3)))
		return (-errno);

	if (stat64(filename, &statbuf) == 0) {
		statbuf.st_mode &= ~S_ISUID;
		if (statbuf.st_mode & S_IXGRP)
			statbuf.st_mode &= ~S_ISGID;
		(void) chmod(filename, (statbuf.st_mode & MODEMASK));
	}

	return (0);
}

int
lx_fchown16(uintptr_t p1, uintptr_t p2, uintptr_t p3)
{
	int fd = (int)p1;
	struct stat64 statbuf;

	if (fchown(fd, LX_UID16_TO_UID32((lx_gid16_t)p2),
	    LX_GID16_TO_GID32((lx_gid16_t)p3)))
		return (-errno);

	if (fstat64(fd, &statbuf) == 0) {
		statbuf.st_mode &= ~S_ISUID;
		if (statbuf.st_mode & S_IXGRP)
			statbuf.st_mode &= ~S_ISGID;
		(void) fchmod(fd, (statbuf.st_mode & MODEMASK));
	}

	return (0);
}

int
lx_lchown16(uintptr_t p1, uintptr_t p2, uintptr_t p3)
{
	return (lchown((char *)p1, LX_UID16_TO_UID32((lx_gid16_t)p2),
	    LX_GID16_TO_GID32((lx_gid16_t)p3)) ? -errno : 0);
}

int
lx_chown(uintptr_t p1, uintptr_t p2, uintptr_t p3)
{
	char *filename = (char *)p1;
	struct stat64 statbuf;
	int ret;

	ret = chown(filename, (uid_t)p2, (gid_t)p3);

	if (ret < 0) {
		/*
		 * If chown() failed and we're in install mode, return success
		 * if the the reason we failed was because the source file
		 * didn't actually exist or if we're trying to modify /dev/pts.
		 */
		if ((lx_install != 0) &&
		    ((errno == ENOENT) || (install_checkpath(p1) == 0)))
			return (0);

		return (-errno);
	}

	if (stat64(filename, &statbuf) == 0) {
		statbuf.st_mode &= ~S_ISUID;
		if (statbuf.st_mode & S_IXGRP)
			statbuf.st_mode &= ~S_ISGID;
		(void) chmod(filename, (statbuf.st_mode & MODEMASK));
	}

	return (0);
}

int
lx_fchown(uintptr_t p1, uintptr_t p2, uintptr_t p3)
{
	int fd = (int)p1;
	struct stat64 statbuf;

	if (fchown(fd, (uid_t)p2, (gid_t)p3))
		return (-errno);

	if (fstat64(fd, &statbuf) == 0) {
		statbuf.st_mode &= ~S_ISUID;
		if (statbuf.st_mode & S_IXGRP)
			statbuf.st_mode &= ~S_ISGID;
		(void) fchmod(fd, (statbuf.st_mode & MODEMASK));
	}

	return (0);
}

int
lx_chmod(uintptr_t p1, uintptr_t p2)
{
	int ret;

	ret = chmod((const char *)p1, (mode_t)p2);

	if (ret < 0) {
		/*
		 * If chown() failed and we're in install mode, return success
		 * if the the reason we failed was because the source file
		 * didn't actually exist or if we're trying to modify /dev/pts.
		 */
		if ((lx_install != 0) &&
		    ((errno == ENOENT) || (install_checkpath(p1) == 0)))
			return (0);

		return (-errno);
	}

	return (0);
}

int
lx_utime(uintptr_t p1, uintptr_t p2)
{
	int ret;

	ret = utime((const char *)p1, (const struct utimbuf *)p2);

	if (ret < 0) {
		/*
		 * If chown() failed and we're in install mode, return success
		 * if the the reason we failed was because the source file
		 * didn't actually exist or if we're trying to modify /dev/pts.
		 */
		if ((lx_install != 0) &&
		    ((errno == ENOENT) || (install_checkpath(p1) == 0)))
			return (0);

		return (-errno);
	}

	return (0);
}

/*
 * llseek() - The Linux implementation takes an additional parameter, which is
 * the resulting position in the file.
 */
int
lx_llseek(uintptr_t p1, uintptr_t p2, uintptr_t p3, uintptr_t p4,
    uintptr_t p5)
{
	offset_t ret;
	offset_t *res = (offset_t *)p4;

	/* SEEK_DATA and SEEK_HOLE are only valid in Solaris */
	if ((int)p5 > SEEK_END)
		return (-EINVAL);

	if ((ret = llseek((int)p1, LX_32TO64(p3, p2), p5)) < 0)
		return (-errno);

	*res = ret;
	return (0);
}

/*
 * seek() - When the resultant file offset cannot be represented in 32 bits,
 * Linux performs the seek but Solaris doesn't, though both set EOVERFLOW.  We
 * call llseek() and then check to see if we need to return EOVERFLOW.
 */
int
lx_lseek(uintptr_t p1, uintptr_t p2, uintptr_t p3)
{
	offset_t offset = (offset_t)(off_t)(p2);	/* sign extend */
	offset_t ret;
	off_t ret32;

	/* SEEK_DATA and SEEK_HOLE are only valid in Solaris */
	if ((int)p3 > SEEK_END)
		return (-EINVAL);

	if ((ret = llseek((int)p1, offset, p3)) < 0)
		return (-errno);

	ret32 = (off_t)ret;
	if ((offset_t)ret32 == ret)
		return (ret32);
	else
		return (-EOVERFLOW);
}

/*
 * Neither Solaris nor Linux actually returns anything to the caller, but glibc
 * expects to see SOME value returned, so placate it and return 0.
 */
int
lx_sync(void)
{
	sync();
	return (0);
}

int
lx_rmdir(uintptr_t p1)
{
	int r;

	r = rmdir((char *)p1);
	if (r < 0)
		return ((errno == EEXIST) ? -ENOTEMPTY : -errno);
	return (0);
}

/*
 * Exactly the same as Solaris' sysfs(2), except Linux numbers their fs indices
 * starting at 0, and Solaris starts at 1.
 */
int
lx_sysfs(uintptr_t p1, uintptr_t p2, uintptr_t p3)
{
	int option = (int)p1;
	int res;

	/*
	 * Linux actually doesn't have #defines for these; their sysfs(2)
	 * man page literally defines the "option" field as being 1, 2 or 3,
	 * corresponding to Solaris' GETFSIND, GETFSTYP and GETNFSTYP,
	 * respectively.
	 */
	switch (option) {
		case 1:
			if ((res = sysfs(GETFSIND, (const char *)p2)) < 0)
				return (-errno);

			return (res - 1);

		case 2:
			if ((res = sysfs(GETFSTYP, (int)p2 + 1,
			    (char *)p3)) < 0)
				return (-errno);

			return (0);

		case 3:
			if ((res = sysfs(GETNFSTYP)) < 0)
				return (-errno);

			return (res);

		default:
			break;
	}

	return (-EINVAL);
}

int
lx_faccessat(uintptr_t p1, uintptr_t p2, uintptr_t p3, uintptr_t p4)
{
	int atfd = (int)p1;
	char *path = (char *)p2;
	int mode = (mode_t)p3;
	int flag = (int)p4;

	if (atfd == LX_AT_FDCWD)
		atfd = AT_FDCWD;

	flag = ltos_at_flag(flag, AT_EACCESS);
	if (flag < 0)
		return (-EINVAL);

	return (faccessat(atfd, path, mode, flag) ? -errno : 0);
}

int
lx_futimesat(uintptr_t p1, uintptr_t p2, uintptr_t p3)
{
	int atfd = (int)p1;
	char *path = (char *)p2;
	struct timeval *times = (struct timeval *)p3;

	if (atfd == LX_AT_FDCWD)
		atfd = AT_FDCWD;

	return (futimesat(atfd, path, times) ? -errno : 0);
}


/*
 * Constructs an absolute path string in buf from the path of fd and the
 * relative path string pointed to by "p1". This is required for emulating
 * *at() system calls.
 * Example:
 *    If the path of fd is "/foo/bar" and path is "etc" the string returned is
 *    "/foo/bar/etc", if the fd is a file fd then it fails with ENOTDIR.
 *    If path is absolute then no modifcations are made to it when copied.
 */
static int
getpathat(int fd, uintptr_t p1, char *outbuf, size_t outbuf_size)
{
	char pathbuf[MAXPATHLEN];
	char fdpathbuf[MAXPATHLEN];
	char *fdpath;
	struct stat64 statbuf;

	if (uucopystr((void *)p1, pathbuf, MAXPATHLEN) == -1)
		return (-errno);

	/* If the path is absolute then we can early out */
	if ((pathbuf[0] == '/') || (fd == LX_AT_FDCWD)) {
		(void) strlcpy(outbuf, pathbuf, outbuf_size);
		return (0);
	}

	fdpath = lx_fd_to_path(fd, fdpathbuf, sizeof (fdpathbuf));
	if (fdpath == NULL)
		return (-EBADF);

	if ((fstat64(fd, &statbuf) < 0))
		return (-EBADF);

	if (!S_ISDIR(statbuf.st_mode))
		return (-ENOTDIR);

	if (snprintf(outbuf, outbuf_size, "%s/%s", fdpath, pathbuf) >
	    (outbuf_size-1))
		return (-ENAMETOOLONG);

	return (0);
}

int
lx_mkdirat(uintptr_t p1, uintptr_t p2, uintptr_t p3)
{
	int atfd = (int)p1;
	mode_t mode = (mode_t)p3;
	char pathbuf[MAXPATHLEN];
	int ret;

	ret = getpathat(atfd, p2, pathbuf, sizeof (pathbuf));
	if (ret < 0)
		return (ret);

	return (mkdir(pathbuf, mode) ? -errno : 0);
}

int
lx_mknodat(uintptr_t ext1, uintptr_t p1, uintptr_t p2, uintptr_t p3)
{
	int atfd = (int)ext1;
	char pathbuf[MAXPATHLEN];
	int ret;

	ret = getpathat(atfd, p1, pathbuf, sizeof (pathbuf));
	if (ret < 0)
		return (ret);

	return (lx_mknod((uintptr_t)pathbuf, p2, p3));
}

int
lx_symlinkat(uintptr_t p1, uintptr_t ext1, uintptr_t p2)
{
	int atfd = (int)ext1;
	char pathbuf[MAXPATHLEN];
	int ret;

	ret = getpathat(atfd, p2, pathbuf, sizeof (pathbuf));
	if (ret < 0)
		return (ret);

	return (symlink((char *)p1, pathbuf) ? -errno : 0);
}

int
lx_linkat(uintptr_t ext1, uintptr_t p1, uintptr_t ext2, uintptr_t p2,
    uintptr_t p3)
{
	int atfd1 = (int)ext1;
	int atfd2 = (int)ext2;
	char pathbuf1[MAXPATHLEN];
	char pathbuf2[MAXPATHLEN];
	int ret;

	/*
	 * The flag specifies whether the hardlink will point to a symlink or
	 * not, on solaris the default behaviour of link() is to dereference a
	 * symlink and there is no obvious way to trigger the other behaviour.
	 * So for now we just ignore this flag and act like link().
	 */
	/* LINTED [set but not used in function] */
	int flag = p3;

	ret = getpathat(atfd1, p1, pathbuf1, sizeof (pathbuf1));
	if (ret < 0)
		return (ret);

	ret = getpathat(atfd2, p2, pathbuf2, sizeof (pathbuf2));
	if (ret < 0)
		return (ret);

	return (lx_link((uintptr_t)pathbuf1, (uintptr_t)pathbuf2));
}

int
lx_readlinkat(uintptr_t ext1, uintptr_t p1, uintptr_t p2, uintptr_t p3)
{
	int atfd = (int)ext1;
	char pathbuf[MAXPATHLEN];
	int ret;

	ret = getpathat(atfd, p1, pathbuf, sizeof (pathbuf));
	if (ret < 0)
		return (ret);

	ret = readlink(pathbuf, (char *)p2, (size_t)p3);
	if (ret < 0)
		return (-errno);

	return (ret);
}

int
lx_fchownat(uintptr_t ext1, uintptr_t p1, uintptr_t p2, uintptr_t p3,
    uintptr_t p4)
{
	int flag;
	int atfd = (int)ext1;
	char pathbuf[MAXPATHLEN];
	int ret;

	flag = ltos_at_flag(p4, AT_SYMLINK_NOFOLLOW);
	if (flag < 0)
		return (-EINVAL);

	ret = getpathat(atfd, p1, pathbuf, sizeof (pathbuf));
	if (ret < 0)
		return (ret);

	if (flag & AT_SYMLINK_NOFOLLOW)
		return (lchown(pathbuf, (uid_t)p2, (gid_t)p3) ? -errno : 0);
	else
		return (lx_chown((uintptr_t)pathbuf, p2, p3));
}

int
lx_fchmodat(uintptr_t ext1, uintptr_t p1, uintptr_t p2, uintptr_t p3)
{
	int atfd = (int)ext1;
	char pathbuf[MAXPATHLEN];
	int ret;

	/*
	 * It seems that at least some versions of glibc do not set or clear
	 * the flags arg, so checking them will result in random behaviour.
	 */
	/* LINTED [set but not used in function] */
	int flag = p3;

	ret = getpathat(atfd, p1, pathbuf, sizeof (pathbuf));
	if (ret < 0)
		return (ret);

	return (lx_chmod((uintptr_t)pathbuf, p2));
}
