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
 * Copyright 2020 OmniOS Community Edition (OmniOSce) Association.
 */

/*
 * Test the implementation of the various *utimes() and *utimens() functions
 */

#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <err.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

timespec_t testtimes[] = {
	{
		.tv_sec = 1280793678,
		.tv_nsec = 123456789
	},
	{
		.tv_sec = 1492732800,
		.tv_nsec = 17
	},
	{
		.tv_sec = 1320796855,
		.tv_nsec = 9
	},
	{
		.tv_sec = 1498953611,
		.tv_nsec = 987654321
	}
};

enum ttype {
	UTIMES,
	LUTIMES,
	FUTIMES,
	FUTIMESAT,
	FUTIMENS,
	UTIMENSAT
};

static bool
compare_times(struct stat *st, bool trunc, timespec_t *atim, timespec_t *mtim,
    bool invert)
{
	bool ret = true;

	if (st->st_atim.tv_sec != atim->tv_sec) {
		ret = false;
	} else if (st->st_atim.tv_nsec != (
	    trunc ? atim->tv_nsec / 1000 * 1000 : atim->tv_nsec)) {
		ret = false;
	} else if (st->st_mtim.tv_sec != mtim->tv_sec) {
		ret = false;
	} else if (st->st_mtim.tv_nsec != (
	    trunc ? mtim->tv_nsec / 1000 * 1000 : mtim->tv_nsec)) {
		ret = false;
	}

	if ((!ret && !invert) || (ret && invert)) {
		printf("    actual atime: %ld.%.9ld\n",
		    st->st_atim.tv_sec, st->st_atim.tv_nsec);
		printf("    actual mtime: %ld.%.9ld\n",
		    st->st_mtim.tv_sec, st->st_mtim.tv_nsec);
	}

	return (ret);
}

static bool
compare_filetime(char *path, bool trunc, timespec_t *atim, timespec_t *mtim,
    bool invert)
{
	struct stat st;

	if (stat(path, &st) == -1)
		err(EXIT_FAILURE, "stat %s", path);

	return (compare_times(&st, trunc, atim, mtim, invert));
}

static bool
compare_linktime(char *path, bool trunc, timespec_t *atim, timespec_t *mtim,
    bool invert)
{
	struct stat st;

	if (lstat(path, &st) == -1)
		err(EXIT_FAILURE, "lstat %s", path);

	return (compare_times(&st, trunc, atim, mtim, invert));
}

static bool
reset(char *path, timespec_t *atim, timespec_t *mtim)
{
	if (utimes(path, NULL) == -1)
		err(EXIT_FAILURE, "utimes reset");
	if (compare_filetime(path, true, atim, mtim, true)) {
		warnx("reset failed");
		return (false);
	}
	return (true);
}

static bool
reset_link(char *lpath, timespec_t *atim, timespec_t *mtim)
{
	if (lutimes(lpath, NULL) == -1)
		err(EXIT_FAILURE, "lutimes reset");
	if (compare_linktime(lpath, true, atim, mtim, true)) {
		warnx("link reset failed");
		return (false);
	}
	return (true);
}

static bool
runtest(enum ttype fn, char *dir, timespec_t *atim, timespec_t *mtim)
{
	char path[MAXPATHLEN + 1];
	char lpath[MAXPATHLEN + 1];
	struct timespec ts[2];
	struct timeval tv[2];
	int fd, lfd, dfd, ret = true;

	ts[0] = *atim;
	ts[1] = *mtim;
	TIMESPEC_TO_TIMEVAL(&tv[0], &ts[0]);
	TIMESPEC_TO_TIMEVAL(&tv[1], &ts[1]);

	if (snprintf(path, sizeof (path), "%s/file", dir) >= sizeof (path))
		err(EXIT_FAILURE, "snprintf failed to build file path");

	if ((fd = open(path, O_CREAT, 0644)) == -1)
		err(EXIT_FAILURE, "open file %s", path);

	if (snprintf(lpath, sizeof (lpath), "%s/link", dir) >= sizeof (path))
		err(EXIT_FAILURE, "snprintf failed to build link path");

	if (symlink(path, lpath) == -1)
		err(EXIT_FAILURE, "link(%s)", lpath);

	if ((lfd = open(lpath, O_RDWR)) == -1)
		err(EXIT_FAILURE, "open link(%s)", lpath);

	if ((dfd = open(dir, O_DIRECTORY|O_RDONLY)) == -1)
		err(EXIT_FAILURE, "open dir(%s)", dir);

	switch (fn) {
	case UTIMES:
		printf("..... utimes()\n");

		if (utimes(path, tv) == -1)
			err(EXIT_FAILURE, "utimes(%s)", path);
		if (!compare_filetime(path, true, atim, mtim, false)) {
			warnx("failed on file");
			ret = false;
		}

		if (!reset(path, atim, mtim))
			ret = false;

		/* repeat against symbolic link path */
		if (utimes(lpath, tv) == -1)
			err(EXIT_FAILURE, "utimes(%s), link", lpath);
		if (!compare_filetime(path, true, atim, mtim, false)) {
			warnx("failed on file through link");
			ret = false;
		}

		break;

	case LUTIMES:
		printf("..... lutimes()\n");

		/* Use lutimes() against a plain file */
		if (lutimes(path, tv) == -1)
			err(EXIT_FAILURE, "lutimes(%s)", path);
		if (!compare_filetime(path, true, atim, mtim, false)) {
			warnx("failed on file");
			ret = false;
		}

		if (!reset(path, atim, mtim))
			ret = false;

		/* Set the time on the link, not on the target */
		if (lutimes(lpath, tv) == -1)
			err(EXIT_FAILURE, "lutimes(%s)", lpath);
		if (!compare_linktime(lpath, true, atim, mtim, false)) {
			warnx("link time is incorrect");
			ret = false;
		}
		if (compare_filetime(path, true, atim, mtim, true)) {
			warnx("target time was updated incorrectly");
			ret = false;
		}

		/* Reset the time on the path and link to the current time */
		if (!reset(path, atim, mtim) || !reset_link(lpath, atim, mtim))
			ret = false;

		/* and modify the target */
		if (utimes(path, tv) == -1)
			err(EXIT_FAILURE, "utimes(%s)", path);
		/* Now the target should match but the link should not */
		if (!compare_filetime(path, true, atim, mtim, false)) {
			warnx("target time is incorrect");
			ret = false;
		}
		if (compare_linktime(lpath, true, atim, mtim, true)) {
			warnx("link time was updated incorrectly");
			ret = false;
		}
		break;

	case FUTIMES:
		printf("..... futimes()\n");

		if (futimes(fd, tv) == -1)
			err(EXIT_FAILURE, "futimes(%s)", path);
		if (!compare_filetime(path, true, atim, mtim, false)) {
			warnx("failed on file");
			ret = false;
		}

		break;

	case FUTIMESAT: {
		int rfd;
		printf("..... futimesat()\n");

		/* NULL path, should modify the file for 'fd' */
		if (futimesat(fd, NULL, tv) == -1)
			err(EXIT_FAILURE, "futimesat(fd, NULL)");
		if (!compare_filetime(path, true, atim, mtim, false)) {
			warnx("failed with null path");
			ret = false;
		}

		if (!reset(path, atim, mtim))
			ret = false;

		/* random descriptor, FQ path, descriptor is ignored */
		if ((rfd = open("/dev/null", O_RDONLY)) == -1)
			err(EXIT_FAILURE, "open(/dev/null)");
		if (futimesat(rfd, path, tv) == -1)
			err(EXIT_FAILURE, "futimesat(dnfd, %s)", path);
		if (!compare_filetime(path, true, atim, mtim, false)) {
			warnx("failed with random descriptor and fq path");
			ret = false;
		}

		if (!reset(path, atim, mtim))
			ret = false;

		/* repeat against symbolic link path */
		if (futimesat(rfd, lpath, tv) == -1)
			err(EXIT_FAILURE, "futimesat(dnfd, %s), link", lpath);
		if (!compare_filetime(path, true, atim, mtim, false)) {
			warnx("failed through link with "
			    "random descriptor, fq path");
			ret = false;
		}

		(void) close(rfd);

		if (!reset(path, atim, mtim))
			ret = false;

		/* relative to a directory */
		if (futimesat(dfd, "file", tv) == -1)
			err(EXIT_FAILURE, "futimesat(dir, file)");
		if (!compare_filetime(path, true, atim, mtim, false)) {
			warnx("failed relative to a directory");
			ret = false;
		}

		if (!reset(path, atim, mtim))
			ret = false;

		/* repeat against symbolic link path */
		if (futimesat(dfd, "link", tv) == -1)
			err(EXIT_FAILURE, "futimesat(dir, link)");
		if (!compare_filetime(path, true, atim, mtim, false)) {
			warnx("failed through link relative to a directory");
			ret = false;
		}

		if (!reset(path, atim, mtim))
			ret = false;

		/* AT_FDCWD */
		if (fchdir(dfd) == -1)
			err(EXIT_FAILURE, "fchdir(%s)", dir);
		if (futimesat(AT_FDCWD, "file", tv) == -1)
			err(EXIT_FAILURE, "futimesat(AT_FDCWD, file)");
		if (!compare_filetime(path, true, atim, mtim, false)) {
			warnx("failed with AT_FDCWD relative");
			ret = false;
		}

		if (!reset(path, atim, mtim))
			ret = false;

		/* repeat against symbolic link path */
		if (futimesat(AT_FDCWD, "link", tv) == -1)
			err(EXIT_FAILURE, "futimesat(AT_FDCWD, link)");
		if (!compare_filetime(path, true, atim, mtim, false)) {
			warnx("failed through link with AT_FDCWD relative");
			ret = false;
		}

		break;
	}

	case FUTIMENS:
		printf("..... futimens()\n");
		if (futimens(fd, ts) == -1)
			err(EXIT_FAILURE, "futimesns(%s)", path);
		if (!compare_filetime(path, false, atim, mtim, false)) {
			warnx("failed with plain file fd");
			ret = false;
		}

		break;

	case UTIMENSAT: {
		int rfd;

		printf("..... utimensat()\n");

		/* NULL path, expect EFAULT (cf. futimesat()) */
		if (utimensat(fd, NULL, ts, 0) != -1 || errno != EFAULT) {
			warnx("null path should return EFAULT but got %d/%s",
			    errno, strerror(errno));
			ret = false;
		}

		/* random descriptor, FQ path, descriptor is ignored */
		if ((rfd = open("/dev/null", O_RDONLY)) == -1)
			err(EXIT_FAILURE, "open(/dev/null)");
		if (utimensat(rfd, path, ts, 0) == -1)
			err(EXIT_FAILURE, "utimensat(dnfd, %s)", path);
		if (!compare_filetime(path, false, atim, mtim, false)) {
			warnx("failed with random descriptor, fq path");
			ret = false;
		}

		if (!reset(path, atim, mtim))
			ret = false;

		/* repeat against symbolic link path */
		if (utimensat(rfd, lpath, ts, 0) == -1)
			err(EXIT_FAILURE, "utimensat(dnfd, link %s)", lpath);
		if (!compare_filetime(path, false, atim, mtim, false)) {
			warnx("failed against link with random descriptor, "
			    "fq path");
			ret = false;
		}

		(void) close(rfd);

		if (!reset(path, atim, mtim))
			ret = false;

		/* relative to a directory */
		if (utimensat(dfd, "file", ts, 0) == -1)
			err(EXIT_FAILURE, "utimensat(dir, file)");
		if (!compare_filetime(path, false, atim, mtim, false)) {
			warnx("failed relative to a directory");
			ret = false;
		}

		if (!reset(path, atim, mtim))
			ret = false;

		/* repeat against symbolic link path */
		if (utimensat(dfd, "link", ts, 0) == -1)
			err(EXIT_FAILURE, "utimensat(dir, link)");
		if (!compare_filetime(path, false, atim, mtim, false)) {
			warnx("failed through link relative to a directory");
			ret = false;
		}

		if (!reset(path, atim, mtim))
			ret = false;

		/* AT_FDCWD */
		if (fchdir(dfd) == -1)
			err(EXIT_FAILURE, "fchdir(%s)", dir);
		if (utimensat(AT_FDCWD, "file", ts, 0) == -1)
			err(EXIT_FAILURE, "utimensat(AT_FDCWD, file)");
		if (!compare_filetime(path, false, atim, mtim, false)) {
			warnx("failed with AT_FDCWD relative");
			ret = false;
		}

		if (!reset(path, atim, mtim))
			ret = false;

		/* repeat against symbolic link path */
		if (utimensat(AT_FDCWD, "link", ts, 0) == -1)
			err(EXIT_FAILURE, "utimensat(AT_FDCWD, link)");
		if (!compare_filetime(path, false, atim, mtim, false)) {
			warnx("failed through link with AT_FDCWD relative");
			ret = false;
		}

		if (!reset(path, atim, mtim))
			ret = false;

		/*
		 * Check that none of the above operations have changed the
		 * timestamp on the link.
		 */
		if (compare_linktime(lpath, true, atim, mtim, true)) {
			warnx("link timestamp was unexpectedly modified");
			ret = false;
		}

		/* Set the time on the link, not on the target */
		if (utimensat(AT_FDCWD, "link", ts, AT_SYMLINK_NOFOLLOW) == -1)
			err(EXIT_FAILURE, "utimensat(AT_FDCWD, lflag)");
		if (!compare_linktime(lpath, false, atim, mtim, false)) {
			warnx("link time is incorrect");
			ret = false;
		}
		if (compare_filetime(path, false, atim, mtim, true)) {
			warnx("target time was updated incorrectly");
			ret = false;
		}
		}
		break;
	}

	(void) close(dfd);
	(void) close(lfd);
	(void) close(fd);

	if (unlink(lpath) == -1)
		err(EXIT_FAILURE, "unlink(%s)", lpath);
	if (unlink(path) == -1)
		err(EXIT_FAILURE, "unlink(%s)", path);

	if (!ret)
		warnx("Test failed");

	return (ret);
}

static bool
runtests(char *dir, timespec_t *atim, timespec_t *mtim)
{
	bool ret = true;

	printf("Testing:\n... atime: %ld.%.9ld\n... mtime: %ld.%.9ld\n",
	    atim->tv_sec, atim->tv_nsec, mtim->tv_sec, mtim->tv_nsec);

	if (!runtest(UTIMES, dir, atim, mtim))
		ret = false;
	if (!runtest(LUTIMES, dir, atim, mtim))
		ret = false;
	if (!runtest(FUTIMES, dir, atim, mtim))
		ret = false;
	if (!runtest(FUTIMESAT, dir, atim, mtim))
		ret = false;
	if (!runtest(FUTIMENS, dir, atim, mtim))
		ret = false;
	if (!runtest(UTIMENSAT, dir, atim, mtim))
		ret = false;

	return (ret);
}

int
main(void)
{
	char dir[] = "/tmp/utimes.XXXXXX";
	int ret = EXIT_SUCCESS;
	int i;

	if (mkdtemp(dir) == NULL)
		err(EXIT_FAILURE, "failed to create temporary directory");

	for (i = 0; i < ARRAY_SIZE(testtimes); i += 2) {
		if (!runtests(dir, &testtimes[i], &testtimes[i + 1]))
			ret = EXIT_FAILURE;
	}

	/*
	 * Some tests will have changed directory into 'dir' to test the
	 * AT_FDCWD case. Change back to / to avoid EBUSY when removing dir.
	 */
	if (chdir("/") == -1)
		err(EXIT_FAILURE, "chdir(/)");
	if (rmdir(dir) == -1)
		err(EXIT_FAILURE, "rmdir %s", dir);

	return (ret);
}
