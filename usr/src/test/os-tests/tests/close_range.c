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
 * Copyright 2026 Oxide Computer Company
 */

/*
 * Tests for close_range(2): range semantics, CLOEXEC/CLOFORK marking,
 * argument validation and the cancellation of outstanding asynchronous
 * I/O against descriptors that are closed. We also exercise
 * closefrom(3C), which is implemented on top of close_range().
 */

#include <aio.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/time.h>

static uint_t failures = 0;

#define	TFAIL(name, fmt, ...)	do {					\
	(void) fprintf(stderr, "TEST FAILED: %s: " fmt "\n",		\
	    (name), ##__VA_ARGS__);					\
	failures++;							\
} while (0)

#define	TPASS(name)	(void) printf("TEST PASSED: %s\n", (name))

/*
 * The test descriptors are pinned at known numbers, comfortably above
 * anything the process opens for itself.
 */
#define	FD_BASE		50
#define	FD_LIMIT	70

static void
open_fds(void)
{
	int fd;

	if ((fd = open("/dev/null", O_RDONLY)) == -1)
		err(EXIT_FAILURE, "could not open /dev/null");

	for (int i = FD_BASE; i < FD_LIMIT; i++) {
		if (dup2(fd, i) != i)
			err(EXIT_FAILURE, "could not dup to fd %d", i);
	}

	(void) close(fd);
}

/*
 * Verify that fd is open and carries precisely the descriptor flags in
 * 'want', or, if want is -1, that fd is closed.
 */
static bool
check_fd(const char *name, int fd, int want)
{
	int fl = fcntl(fd, F_GETFD);

	if (want == -1) {
		if (fl != -1) {
			TFAIL(name, "fd %d unexpectedly open (flags %#x)",
			    fd, fl);
			return (false);
		}
		if (errno != EBADF) {
			TFAIL(name, "fd %d: got errno %s, wanted EBADF",
			    fd, strerrorname_np(errno));
			return (false);
		}
		return (true);
	}

	if (fl == -1) {
		TFAIL(name, "fd %d unexpectedly closed", fd);
		return (false);
	}
	if ((fl & (FD_CLOEXEC | FD_CLOFORK)) != want) {
		TFAIL(name, "fd %d flags %#x, expected %#x", fd, fl, want);
		return (false);
	}
	return (true);
}

static bool
check_range(const char *name, int low, int high, int want)
{
	bool pass = true;

	for (int fd = low; fd <= high; fd++) {
		if (!check_fd(name, fd, want))
			pass = false;
	}
	return (pass);
}

static void
expect_einval(const char *name, uint_t low, uint_t high, int flags)
{
	int ret = close_range(low, high, flags);

	if (ret != -1) {
		TFAIL(name, "close_range returned %d, expected failure", ret);
		return;
	}
	if (errno != EINVAL) {
		TFAIL(name, "got errno %s, wanted EINVAL",
		    strerrorname_np(errno));
		return;
	}
	TPASS(name);
}

/*
 * Render an aio_error() result, or the -1 used here to indicate a
 * timeout, for a failure message.
 */
static const char *
errname(int e)
{
	const char *n;

	if (e == -1)
		return ("EINPROGRESS (timed out)");
	if (e == 0)
		return ("success");
	if ((n = strerrorname_np(e)) == NULL)
		return ("unknown error");
	return (n);
}

/*
 * Create a pipe with the read end at the requested descriptor, returning
 * the write end.
 */
static int
pipe_at(int rfd)
{
	int p[2];

	if (pipe(p) == -1)
		err(EXIT_FAILURE, "pipe");
	if (dup2(p[0], rfd) != rfd)
		err(EXIT_FAILURE, "could not dup pipe to fd %d", rfd);
	(void) close(p[0]);
	return (p[1]);
}

/*
 * Start an asynchronous read against fd. The pipes used here are kept
 * empty, so the request stays outstanding until data arrives or it is
 * cancelled.
 */
static void
start_aio(struct aiocb *cb, int fd, char *buf, size_t bufsz)
{
	(void) memset(cb, 0, sizeof (*cb));
	cb->aio_fildes = fd;
	cb->aio_buf = buf;
	cb->aio_nbytes = bufsz;
	if (aio_read(cb) != 0)
		err(EXIT_FAILURE, "aio_read(fd %d)", fd);
}

/*
 * Wait for an asynchronous request to leave the in-progress state and
 * return its final aio_error() value, or -1 if it is still in progress
 * after five seconds.
 */
static int
await_aio(const struct aiocb *cb)
{
	const struct timespec ts = { .tv_sec = 0, .tv_nsec = MSEC2NSEC(1) };

	for (int i = 0; i < 5000; i++) {
		int e = aio_error(cb);

		if (e != EINPROGRESS)
			return (e);
		(void) nanosleep(&ts, NULL);
	}
	return (-1);
}

/*
 * Closing a range must cancel outstanding user-level aio requests
 * against the descriptors within it, and only those. A range that is
 * only having descriptor flags set must not disturb aio at all.
 */
static void
run_aio_tests(void)
{
	struct aiocb cb_range, cb_below, cb_flag, cb_from;
	char buf_range[4], buf_below[4], buf_flag[4], buf_from[4];
	ssize_t rv;
	int wfd, e;

	(void) pipe_at(80);
	wfd = pipe_at(40);
	start_aio(&cb_range, 80, buf_range, sizeof (buf_range));
	start_aio(&cb_below, 40, buf_below, sizeof (buf_below));

	/* Closing a range cancels requests against descriptors within it */
	if (close_range(60, UINT_MAX, 0) != 0)
		err(EXIT_FAILURE, "close_range(60, UINT_MAX, 0)");
	if ((e = await_aio(&cb_range)) != ECANCELED) {
		TFAIL("aio-cancel-range", "request finished with %s, "
		    "wanted ECANCELED", errname(e));
	} else if (aio_return(&cb_range) != -1) {
		TFAIL("aio-cancel-range", "aio_return did not report an "
		    "error after cancellation");
	} else if (check_fd("aio-cancel-range", 80, -1)) {
		TPASS("aio-cancel-range");
	}

	/* Requests against descriptors below the range are untouched */
	if (write(wfd, "ok", 2) != 2)
		err(EXIT_FAILURE, "write to pipe");
	if ((e = await_aio(&cb_below)) != 0) {
		TFAIL("aio-below-range", "request finished with %s, "
		    "wanted success", errname(e));
	} else if ((rv = aio_return(&cb_below)) != 2) {
		TFAIL("aio-below-range", "aio_return gave %zd, wanted 2", rv);
	} else {
		TPASS("aio-below-range");
	}

	/* Setting descriptor flags must not cancel outstanding aio */
	start_aio(&cb_flag, 40, buf_flag, sizeof (buf_flag));
	if (close_range(40, 40, CLOSE_RANGE_CLOFORK) != 0)
		err(EXIT_FAILURE, "close_range(40, 40, CLOSE_RANGE_CLOFORK)");
	if (close_range(40, 40, CLOSE_RANGE_CLOEXEC) != 0)
		err(EXIT_FAILURE, "close_range(40, 40, CLOSE_RANGE_CLOEXEC)");
	e = aio_error(&cb_flag);
	if (write(wfd, "ok", 2) != 2)
		err(EXIT_FAILURE, "write to pipe");
	if (e != EINPROGRESS) {
		TFAIL("aio-mark-keeps", "request no longer in progress "
		    "after flag marking: %s", errname(e));
	} else if ((e = await_aio(&cb_flag)) != 0) {
		TFAIL("aio-mark-keeps", "request finished with %s, "
		    "wanted success", errname(e));
	} else if ((rv = aio_return(&cb_flag)) != 2) {
		TFAIL("aio-mark-keeps", "aio_return gave %zd, wanted 2", rv);
	} else if (check_fd("aio-mark-keeps", 40, FD_CLOEXEC | FD_CLOFORK)) {
		TPASS("aio-mark-keeps");
	}

	/* closefrom() cancels through the same path */
	(void) pipe_at(80);
	start_aio(&cb_from, 80, buf_from, sizeof (buf_from));
	closefrom(80);
	if ((e = await_aio(&cb_from)) != ECANCELED) {
		TFAIL("aio-cancel-closefrom", "request finished with %s, "
		    "wanted ECANCELED", errname(e));
	} else if (check_fd("aio-cancel-closefrom", 80, -1)) {
		TPASS("aio-cancel-closefrom");
	}
}

int
main(void)
{
	open_fds();

	/* Invalid arguments. An empty high range so a bug cannot bite. */
	expect_einval("low-gt-high", 5, 4, 0);
	expect_einval("flag-unknown", 1000000, 1000001, 1 << 2);
	expect_einval("flag-junk", 1000000, 1000001, ~0);

	/* A range beyond every open descriptor succeeds and does nothing */
	if (close_range(1000000, UINT_MAX, 0) != 0) {
		TFAIL("range-empty", "failed: %s", strerrorname_np(errno));
	} else {
		TPASS("range-empty");
	}

	/* A low bound above INT_MAX must not close anything */
	if (close_range(0x80000000U, UINT_MAX, 0) != 0) {
		TFAIL("low-gt-intmax", "failed: %s",
		    strerrorname_np(errno));
	} else if (check_range("low-gt-intmax", FD_BASE, FD_LIMIT - 1, 0)) {
		TPASS("low-gt-intmax");
	}

	/* Close the middle of the block and check the neighbours */
	if (close_range(55, 59, 0) != 0)
		err(EXIT_FAILURE, "close_range(55, 59, 0)");
	if (check_range("close-mid", 50, 54, 0) &&
	    check_range("close-mid", 55, 59, -1) &&
	    check_range("close-mid", 60, 69, 0)) {
		TPASS("close-mid");
	}

	/* Mark ranges with each flag, then both together */
	if (close_range(60, 64, CLOSE_RANGE_CLOEXEC) != 0)
		err(EXIT_FAILURE, "close_range(CLOSE_RANGE_CLOEXEC)");
	if (check_range("mark-cloexec", 60, 64, FD_CLOEXEC) &&
	    check_range("mark-cloexec", 65, 69, 0)) {
		TPASS("mark-cloexec");
	}

	if (close_range(65, 67, CLOSE_RANGE_CLOFORK) != 0)
		err(EXIT_FAILURE, "close_range(CLOSE_RANGE_CLOFORK)");
	if (check_range("mark-clofork", 65, 67, FD_CLOFORK) &&
	    check_range("mark-clofork", 68, 69, 0)) {
		TPASS("mark-clofork");
	}

	/* Adding a second flag must preserve the first */
	if (close_range(65, 67, CLOSE_RANGE_CLOEXEC) != 0)
		err(EXIT_FAILURE, "close_range(add CLOSE_RANGE_CLOEXEC)");
	if (check_range("mark-accumulate", 65, 67, FD_CLOEXEC | FD_CLOFORK))
		TPASS("mark-accumulate");

	if (close_range(68, 69,
	    CLOSE_RANGE_CLOEXEC | CLOSE_RANGE_CLOFORK) != 0) {
		err(EXIT_FAILURE, "close_range(both flags)");
	}
	if (check_range("mark-both", 68, 69, FD_CLOEXEC | FD_CLOFORK))
		TPASS("mark-both");

	/* Marking a range that includes closed descriptors skips them */
	if (close_range(55, 64, CLOSE_RANGE_CLOEXEC) != 0)
		err(EXIT_FAILURE, "close_range over closed fds");
	if (check_range("mark-gaps", 55, 59, -1) &&
	    check_range("mark-gaps", 60, 64, FD_CLOEXEC)) {
		TPASS("mark-gaps");
	}

	/* The closefrom() form: everything at or above low goes */
	if (close_range(52, UINT_MAX, 0) != 0)
		err(EXIT_FAILURE, "close_range(52, UINT_MAX, 0)");
	if (check_range("close-from", 50, 51, 0) &&
	    check_range("close-from", 52, FD_LIMIT - 1, -1)) {
		TPASS("close-from");
	}

	/* And closefrom(3C) itself, now built on close_range() */
	open_fds();
	closefrom(FD_BASE + 1);
	if (check_fd("closefrom", FD_BASE, 0) &&
	    check_range("closefrom", FD_BASE + 1, FD_LIMIT - 1, -1)) {
		TPASS("closefrom");
	}

	run_aio_tests();

	if (failures == 0) {
		(void) printf("All tests passed\n");
		return (EXIT_SUCCESS);
	}

	(void) fprintf(stderr, "%u test(s) failed\n", failures);
	return (EXIT_FAILURE);
}
