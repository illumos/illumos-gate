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
 * This provides a basic wrapper for tests around the syncfs(3C) operation. As
 * it's difficult to inject I/O failures, we specifically test the following:
 *
 *  - Verify that an invalid fd will result in EBADF
 *  - Use file systems that we know will never support syncfs() and get ENOSYS.
 *    For this we use bootfs, objfs, sockets, and related.
 *  - Attempt to find something that we know will support syncfs() and try to
 *    use it. This last one is the trickiest, we rely on the fact that we know
 *    /var/run will be a tmpfs, but allow additional paths to be specified on
 *    the command line to try.
 */

#include <stdlib.h>
#include <err.h>
#include <unistd.h>
#include <stdbool.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/sysmacros.h>
#include <sys/debug.h>
#include <limits.h>
#include <port.h>

typedef struct syncfs_enosys {
	int (*se_open)(const struct syncfs_enosys *);
	const char *se_path;
} syncfs_enosys_t;

static int
syncfs_open_file(const syncfs_enosys_t *test)
{
	int fd = open(test->se_path, O_RDONLY);
	if (fd < 0) {
		err(EXIT_FAILURE, "TEST FAILED: failed to open file %s",
		    test->se_path);
	}

	return (fd);
}

static int
syncfs_open_socket(const syncfs_enosys_t *test)
{
	struct sockaddr_in in;
	int fd = socket(PF_INET, SOCK_STREAM, 0);
	if (fd < 0) {
		err(EXIT_FAILURE, "TEST FAILED: failed to create basic "
		    "socket");
	}

	(void) memset(&in, 0, sizeof (in));
	if (bind(fd, (struct sockaddr *)&in, sizeof (in)) != 0) {
		err(EXIT_FAILURE, "TEST FAILED: failed to bind socket");
	}

	return (fd);
}

static int
syncfs_open_uds(const syncfs_enosys_t *test)
{
	int fd = socket(PF_UNIX, SOCK_STREAM, 0);
	if (fd < 0) {
		err(EXIT_FAILURE, "TEST FAILED: failed to create UDS");
	}

	return (fd);
}

static int
syncfs_open_pipe(const syncfs_enosys_t *test)
{
	int fds[2];

	if (pipe(fds) != 0) {
		err(EXIT_FAILURE, "TEST FAILED: failed to create pipe");
	}

	VERIFY0(close(fds[1]));
	return (fds[0]);
}

static int
syncfs_open_port(const syncfs_enosys_t *test)
{
	int fd = port_create();
	if (fd < 0) {
		err(EXIT_FAILURE, "TEST FAILED: failed to create event port");
	}

	return (fd);
}

static const syncfs_enosys_t syncfs_enosys[] = {
	{ syncfs_open_file, "/system/boot" },
	{ syncfs_open_file, "/system/object" },
	{ syncfs_open_file, "/proc/self/psinfo" },
	{ syncfs_open_file, "/dev/tcp" },
	{ syncfs_open_file, "/dev/null" },
	{ syncfs_open_file, "/dev/net" },
	{ syncfs_open_file, "/etc/dfs/sharetab" },
	{ syncfs_open_socket, "localhost socket" },
	{ syncfs_open_uds, "UDS socket" },
	{ syncfs_open_pipe, "pipe" },
	{ syncfs_open_file, "/var/run/name_service_door" },
	{ syncfs_open_port, "event port" },
};

static const int syncfs_badfs[] = { -1, STDERR_FILENO + 1, INT_MAX - 1,
    0x7777, -0x7777 };

static bool
syncfs_fail(const char *desc, int fd, int exp_err)
{
	int ret = syncfs(fd);
	if (ret != -1) {
		warnx("TEST FAILED: %s: syncfs succeeded, but expected "
		    "failure", desc);
		return (false);
	}

	if (errno != exp_err) {
		warnx("TEST FAILED: %s: syncfs returned %s, expected %s",
		    desc, strerrorname_np(ret), strerrorname_np(exp_err));
		return (false);
	}

	(void) printf("TEST PASSED: %s\n", desc);
	return (true);
}

static bool
syncfs_pass(const char *path)
{
	bool ret = true;
	int fd = open(path, O_RDONLY);
	if (fd < 0) {
		err(EXIT_FAILURE, "failed to open %s", path);
	}

	if (syncfs(fd) != 0) {
		warnx("TEST FAILED: syncfs failed with %s on %s",
		    strerrorname_np(errno), path);
		ret = false;
	} else {
		(void) printf("TEST PASSED: syncfs returned 0 on %s\n", path);
	}

	VERIFY0(close(fd));
	return (ret);
}

int
main(int argc, char *argv[])
{
	int ret = EXIT_SUCCESS;

	closefrom(STDERR_FILENO + 1);

	for (size_t i = 0; i < ARRAY_SIZE(syncfs_badfs); i++) {
		char msg[PATH_MAX];
		(void) snprintf(msg, sizeof (msg), "Invalid file descriptor "
		    "returns EBADF (%zu)", i);
		if (!syncfs_fail(msg, syncfs_badfs[i], EBADF)) {
			ret = EXIT_FAILURE;
		}
	}

	for (size_t i = 0; i < ARRAY_SIZE(syncfs_enosys); i++) {
		char msg[PATH_MAX];
		int fd = syncfs_enosys[i].se_open(&syncfs_enosys[i]);
		(void) snprintf(msg, sizeof (msg), "Unsupported fs returns "
		    "ENOSYS: %s", syncfs_enosys[i].se_path);
		if (!syncfs_fail(msg, fd, ENOSYS)) {
			ret = EXIT_FAILURE;
		}

		VERIFY0(close(fd));
	}

	if (!syncfs_pass("/var/run")) {
		ret = EXIT_FAILURE;
	}

	for (int i = 1; i < argc; i++) {
		if (!syncfs_pass(argv[i])) {
			ret = EXIT_FAILURE;
		}
	}

	if (ret == EXIT_SUCCESS) {
		(void) printf("All tests completed successfully\n");
	}

	return (ret);
}
