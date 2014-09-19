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
 * Copyright (c) 2014, Joyent, Inc.  All rights reserved.
 */

#include <sys/inotify.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <strings.h>
#include <dirent.h>

int
inotify_init()
{
	return (open("/dev/inotify", O_RDWR));
}

int
inotify_init1(int flags)
{
	int oflags = O_RDWR;

	if (flags & IN_NONBLOCK)
		oflags |= O_NONBLOCK;

	if (flags & IN_CLOEXEC)
		oflags |= O_CLOEXEC;

	return (open("/dev/inotify", oflags));
}

int
inotify_add_watch(int fd, const char *pathname, uint32_t mask)
{
	inotify_addwatch_t ioc;
	inotify_addchild_t cioc;
	struct stat buf;
	int dirfd, wd;
	DIR *dir;
	struct dirent *dp;
	int oflags = O_RDONLY;

	if (mask & IN_DONT_FOLLOW)
		oflags |= O_NOFOLLOW;

	if ((dirfd = open(pathname, oflags)) < 0)
		return (-1);

	if (fstat(dirfd, &buf) != 0) {
		(void) close(dirfd);
		return (-1);
	}

	if ((mask & IN_ONLYDIR) && !(buf.st_mode & S_IFDIR)) {
		(void) close(dirfd);
		errno = ENOTDIR;
		return (-1);
	}

	bzero(&ioc, sizeof (ioc));
	ioc.inaw_fd = dirfd;
	ioc.inaw_mask = mask;

	if ((wd = ioctl(fd, INOTIFYIOC_ADD_WATCH, &ioc)) < 0) {
		(void) close(dirfd);
		return (-1);
	}

	if (!(buf.st_mode & S_IFDIR) || !(mask & IN_CHILD_EVENTS)) {
		(void) close(dirfd);
		(void) ioctl(fd, INOTIFYIOC_ACTIVATE, wd);
		return (wd);
	}

	/*
	 * If we have a directory and we have a mask that denotes child events,
	 * we need to manually add a child watch to every directory entry.
	 * (Because our watch is in place, it will automatically be added to
	 * files that are newly created after this point.)
	 */
	if ((dir = fdopendir(dirfd)) == NULL) {
		(void) inotify_rm_watch(fd, wd);
		(void) close(dirfd);
		return (-1);
	}

	bzero(&cioc, sizeof (cioc));
	cioc.inac_fd = dirfd;

	while ((dp = readdir(dir)) != NULL) {
		if (strcmp(dp->d_name, ".") == 0)
			continue;

		if (strcmp(dp->d_name, "..") == 0)
			continue;

		cioc.inac_name = dp->d_name;

		if (ioctl(fd, INOTIFYIOC_ADD_CHILD, &cioc) != 0) {
			/*
			 * If we get an error that indicates clear internal
			 * malfunctioning, we propagate the error.  Otherwise
			 * we eat it:  this could be a file that no longer
			 * exists or a symlink or something else that we
			 * can't lookup.
			 */
			switch (errno) {
			case ENXIO:
			case EFAULT:
			case EBADF:
				(void) closedir(dir);
				inotify_rm_watch(fd, wd);
				return (-1);
			default:
				break;
			}
		}
	}

	(void) closedir(dir);
	(void) ioctl(fd, INOTIFYIOC_ACTIVATE, wd);

	return (wd);
}

int
inotify_rm_watch(int fd, int wd)
{
	return (ioctl(fd, INOTIFYIOC_RM_WATCH, wd));
}
