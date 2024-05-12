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
 * Copyright 2024 Oxide Computer Company
 */

/*
 * Verify that FIFOs now track tv_nsec in addition to tv_sec. This is important
 * for both named pipes in the file system created with mknod(2) and anonymous
 * pipes created with pipe(2). As part of this, we go through a series of
 * operations on a pipe:
 *
 * 1) Creating it
 * 2) Writing and reading from it to verify the mtime / atime are increasing.
 * 3) Explicitly setting the time on it.
 *
 * At each point, these should advance and we should be bracketed by calls to
 * getting the real time clock.
 */

#include <err.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/debug.h>
#include <stdlib.h>
#include <stdbool.h>
#include <inttypes.h>
#include <fcntl.h>

typedef enum {
	CHK_ATIME_GT	 = 1 << 0,
	CHK_MTIME_GT	 = 1 << 1,
	CHK_CTIME_GT	 = 1 << 2,
	CHK_ATIME_LT	 = 1 << 3,
	CHK_MTIME_LT	 = 1 << 4,
	CHK_CTIME_LT	 = 1 << 5
} check_time_t;

#define	CHK_ALL_GT	(CHK_ATIME_GT | CHK_MTIME_GT | CHK_CTIME_GT)
#define	CHK_ALL_LT	(CHK_ATIME_LT | CHK_MTIME_LT | CHK_CTIME_LT)

static struct timespec now;
static const char *curtype;

static void
update_time(void)
{
	VERIFY0(clock_gettime(CLOCK_REALTIME, &now));
}

static bool
time_gt(const struct timespec *check, const struct timespec *base)
{
	if (check->tv_sec > base->tv_sec) {
		return (true);
	}

	return (check->tv_sec == base->tv_sec &&
	    check->tv_nsec > base->tv_nsec);
}

static bool
check_times(const struct stat *st, check_time_t chk, const char *side,
    const char *desc)
{
	bool ret = true;

	if (((chk & CHK_ATIME_GT) != 0) && !time_gt(&st->st_atim, &now)) {
		warnx("TEST FAILED: %s %s side %s atime is in the past!",
		    curtype, side, desc);
		ret = false;
	}

	if (((chk & CHK_MTIME_GT) != 0) && !time_gt(&st->st_mtim, &now)) {
		warnx("TEST FAILED: %s %s side %s mtime is in the past!",
		    curtype, side, desc);
		ret = false;
	}

	if (((chk & CHK_CTIME_GT) != 0) && !time_gt(&st->st_ctim, &now)) {
		warnx("TEST FAILED: %s %s side %s ctime is in the past!",
		    curtype, side, desc);
		ret = false;
	}

	if (((chk & CHK_ATIME_LT) != 0) && !time_gt(&now, &st->st_atim)) {
		warnx("TEST FAILED: %s %s side %s atime erroneously advanced!",
		    curtype, side, desc);
		ret = false;
	}

	if (((chk & CHK_MTIME_LT) != 0) && !time_gt(&now, &st->st_mtim)) {
		warnx("TEST FAILED: %s %s side %s mtime erroneously advanced!",
		    curtype, side, desc);
		ret = false;
	}

	if (((chk & CHK_CTIME_LT) != 0) && !time_gt(&now, &st->st_ctim)) {
		warnx("TEST FAILED: %s %s side %s ctime erroneously advanced!",
		    curtype, side, desc);
		ret = false;
	}


	return (ret);
}

static bool
check_fifos(int wfd, int rfd)
{
	bool ret = true;
	struct stat st;
	const uint32_t val = 0x7777;
	uint32_t data;
	struct timespec update[2];

	VERIFY0(fstat(wfd, &st));
	if (check_times(&st, CHK_ALL_GT, "write", "creation")) {
		ret = false;
	}

	VERIFY0(fstat(rfd, &st));
	if (check_times(&st, CHK_ALL_GT, "read", "creation")) {
		ret = false;
	}

	/*
	 * Now that we have made progress, write to the write side and confirm
	 * that the mtime / ctime have advanced. The read side should also have
	 * had the mtime / ctime advance.
	 */
	update_time();
	if (write(wfd, &val, sizeof (val)) != sizeof (val)) {
		errx(EXIT_FAILURE, "failed to write value to %s write side",
		    curtype);
	}

	VERIFY0(fstat(wfd, &st));
	if (check_times(&st, CHK_CTIME_GT | CHK_MTIME_GT | CHK_ATIME_LT,
	    "write", "post-write")) {
		ret = false;
	}

	VERIFY0(fstat(rfd, &st));
	if (check_times(&st, CHK_CTIME_GT | CHK_MTIME_GT | CHK_ATIME_LT,
	    "read", "post-write")) {
		ret = false;
	}

	update_time();
	if (read(rfd, &data, sizeof (data)) != sizeof (data)) {
		errx(EXIT_FAILURE, "failed to read data from %s read side",
		    curtype);
	}

	VERIFY0(fstat(rfd, &st));
	if (check_times(&st, CHK_CTIME_LT | CHK_MTIME_LT | CHK_ATIME_GT,
	    "read", "post-read")) {
		ret = false;
	}

	VERIFY0(fstat(wfd, &st));
	if (check_times(&st, CHK_CTIME_LT | CHK_MTIME_LT | CHK_ATIME_GT,
	    "write", "post-read")) {
		ret = false;
	}

	update_time();
	update[0] = now;
	update[1] = now;
	VERIFY0(futimens(wfd, update));

	update_time();
	VERIFY0(fstat(wfd, &st));
	if (check_times(&st, CHK_ALL_LT, "write", "post-futimens")) {
		ret = false;
	}

	VERIFY0(fstat(rfd, &st));
	if (check_times(&st, CHK_ALL_LT, "read", "post-futimens")) {
		ret = false;
	}

	return (ret);
}

int
main(void)
{
	int ret = EXIT_SUCCESS;
	int pipes[2];
	char path[1024];

	update_time();
	if (pipe(pipes) != 0) {
		err(EXIT_FAILURE, "failed to create pipes");
	}

	curtype = "pipe(2)";
	if (!check_fifos(pipes[0], pipes[1])) {
		ret = EXIT_FAILURE;
	}

	VERIFY0(close(pipes[0]));
	VERIFY0(close(pipes[1]));

	(void) snprintf(path, sizeof (path), "/tmp/fifo-tvnsec.%" _PRIdID
	    ".fifo", getpid());
	if (mkfifo(path, 0666) != 0) {
		err(EXIT_FAILURE, "failed to create fifo");
	}

	/*
	 * We have to open the read side before the write side and must make
	 * sure that we use a non-blocking open because this is all coming from
	 * the same process.
	 */
	pipes[1] = open(path, O_RDONLY | O_NONBLOCK);
	if (pipes[1] < 0) {
		err(EXIT_FAILURE, "failed to open %s read-only", path);
	}

	pipes[0] = open(path, O_WRONLY | O_NONBLOCK);
	if (pipes[0] < 0) {
		err(EXIT_FAILURE, "failed to open %s write-only", path);
	}

	curtype = "mkfifo(3C)";
	if (!check_fifos(pipes[0], pipes[1])) {
		ret = EXIT_FAILURE;
	}
	(void) unlink(path);

	return (ret);
}
