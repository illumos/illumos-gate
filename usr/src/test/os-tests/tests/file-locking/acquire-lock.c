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

/*
 * Acquire the specified kind of lock with the specified parameters. After
 * acquiring the lock, a byte will be written to stdout. The program will
 * then wait for a byte to be written to stdin before exiting.
 *
 * Usage: <posix|ofd|flock> <shared|exclusive> <path>
 */

#include "util.h"
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <sys/file.h>
#include <unistd.h>


static	void	acq_fcntl(int, int, int);
static	void	acq_flock(int fd, int mode);
static	void	acq_run(int, lock_style_t, boolean_t);


static void
acq_fcntl(int fd, int cmd, int mode)
{
	struct flock fl;
	int ret, i;

	/*
	 * Acquire the lock, and then try reacquiring it several times. Once we
	 * have acquired the lock, trying to acquire it again should succeed,
	 * and shouldn't upgrade, downgrade or free the lock.
	 */
	for (i = 0; i < 3; i++) {
		flock_reinit(&fl, mode);
		flock_log("Acquiring lock (fcntl)...\n");
		ret = fcntl(fd, cmd, &fl);
		if (ret == -1) {
			err(EXIT_FAILURE, "fcntl failed");
		}
	}


	/* Let the parent know we have the lock and wait */
	flock_log("Waiting (fcntl)...\n");
	flock_alert(1);
	flock_block(0);

	/* Now unlock */
	flock_reinit(&fl, F_UNLCK);
	flock_log("Releasing lock (fcntl)...\n");
	ret = fcntl(fd, cmd, &fl);
	if (ret == -1) {
		err(EXIT_FAILURE, "fcntl failed");
	}
}


static void
acq_flock(int fd, int mode)
{
	int ret, i;

	/*
	 * Acquire the lock, and then try reacquiring it several times. Once we
	 * have acquired the lock, trying to acquire it again should succeed,
	 * and shouldn't upgrade, downgrade or free the lock.
	 */
	for (i = 0; i < 3; i++) {
		flock_log("Acquiring lock (flock)...\n");
		ret = flock(fd, mode);
		if (ret == -1) {
			err(EXIT_FAILURE, "flock failed");
		}
	}

	/* Wait to be okayed to unlock */
	flock_log("Waiting (flock)...\n");
	flock_alert(1);
	flock_block(0);

	/* Release lock */
	flock_log("Releasing lock (flock)...\n");
	ret = flock(fd, LOCK_UN);
	if (ret == -1) {
		err(EXIT_FAILURE, "flock failed");
	}
}


static void
acq_run(int fd, lock_style_t style, boolean_t is_exclusive)
{
	switch (style) {
	case LSTYLE_POSIX:
		acq_fcntl(fd, F_SETLKW, is_exclusive ? F_WRLCK : F_RDLCK);
		break;
	case LSTYLE_OFD:
		acq_fcntl(fd, F_OFD_SETLKW, is_exclusive ? F_WRLCK : F_RDLCK);
		break;
	case LSTYLE_FLOCK:
		acq_flock(fd, is_exclusive ? LOCK_EX : LOCK_SH);
		break;
	default:
		abort();
	}
}


int
main(int argc, char *argv[])
{
	char *modestr, *path;
	lock_style_t style;
	boolean_t is_exclusive;
	int fd;

	if (argc < 4) {
		errx(EXIT_FAILURE, BAD_ARGS_MESSAGE, argc - 1);
	}

	modestr = argv[2];
	path = argv[3];

	style = flock_styleenum(argv[1]);

	if (strcmp(modestr, "shared") == 0) {
		is_exclusive = B_FALSE;
	} else if (strcmp(modestr, "exclusive") == 0) {
		is_exclusive = B_TRUE;
	} else {
		errx(EXIT_FAILURE, BAD_MODE_MESSAGE);
	}

	boolean_t rdonly = style == LSTYLE_FLOCK || !is_exclusive;
	fd = open(path, rdonly ? O_RDONLY : O_WRONLY);
	if (fd == -1) {
		err(EXIT_FAILURE, "Failed to open %s", path);
	}

	acq_run(fd, style, is_exclusive);

	return (0);
}
