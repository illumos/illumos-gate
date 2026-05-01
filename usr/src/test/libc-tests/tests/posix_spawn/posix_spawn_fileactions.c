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
 * Tests for posix_spawn file actions: addopen, addclose, adddup2, and
 * addclosefrom_np. Also tests interactions between file actions and
 * descriptors marked FD_CLOFORK or FD_CLOEXEC in the parent.
 */

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <limits.h>
#include <spawn.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <wait.h>
#include <sys/sysmacros.h>
#include <sys/debug.h>

#include "posix_spawn_common.h"

#define	SFT_MAXFDS	4

typedef struct spawn_fa_test spawn_fa_test_t;
typedef bool (*action_setup_fn_t)(spawn_fa_test_t *,
    posix_spawn_file_actions_t *);
typedef bool (*action_pre_fn_t)(spawn_fa_test_t *);

struct spawn_fa_test {
	const char		*sft_name;
	action_setup_fn_t	sft_setup;
	size_t			sft_nfds;
	int			sft_fds[SFT_MAXFDS];
	spawn_fd_result_t	sft_expected[SFT_MAXFDS];
	int			sft_open_fd;
	const char		*sft_open_path;
	int			sft_open_flags;
	int			sft_close_fd;
	int			sft_dup2_from;
	int			sft_dup2_to;
	/*
	 * Optional parent-side setup, run before the file actions setup.
	 * This callback is also responsible for updating fields in the test
	 * when they refer to runtime-allocated descriptors.
	 */
	action_pre_fn_t		sft_pre;
	int			sft_parent_fd;
	/* If non-zero, posix_spawn(3C) is expected to fail with this errno */
	int			sft_expect_errno;
};

static char posix_spawn_child_path[PATH_MAX];

/*
 * Read fd results from the pipe and verify against expected values.
 */
static bool
spawn_verify_fds(const char *desc, int pipefd,
    const spawn_fd_result_t *expected, size_t count)
{
	bool ret = true;

	for (size_t i = 0; i < count; i++) {
		spawn_fd_result_t res;
		ssize_t n;

		n = read(pipefd, &res, sizeof (res));
		if (n != sizeof (res)) {
			warnx("TEST FAILED: %s: "
			    "failed to read result %zu from pipe "
			    "(got %zd bytes)", desc, i, n);
			return (false);
		}

		if (res.srf_fd != expected[i].srf_fd) {
			warnx("TEST FAILED: %s: "
			    "result %zu: expected fd %d, got %d",
			    desc, i, expected[i].srf_fd, res.srf_fd);
			ret = false;
			continue;
		}

		if (res.srf_open != expected[i].srf_open) {
			warnx("TEST FAILED: %s: fd %d: expected %s, got %s",
			    desc, res.srf_fd,
			    expected[i].srf_open ? "open" : "closed",
			    res.srf_open ? "open" : "closed");
			ret = false;
			continue;
		}

		if (expected[i].srf_open &&
		    res.srf_flags != expected[i].srf_flags) {
			warnx("TEST FAILED: %s: fd %d: expected flags 0x%x, "
			    "got 0x%x", desc, res.srf_fd,
			    expected[i].srf_flags, res.srf_flags);
			ret = false;
			continue;
		}
	}

	return (ret);
}

/*
 * Common test runner. Optionally runs a parent-side pre-test callback,
 * sets up a pipe, calls the test's setup callback to add test-specific
 * file actions, spawns posix_spawn_child in "fds" mode, and verifies
 * the results against the expected values in the test struct.
 *
 * If the test specifies sft_expect_errno, posix_spawn is expected to
 * fail with that errno; in that case the helper is not run.
 */
static bool
spawn_test_fds(spawn_fa_test_t *test)
{
	const char *desc = test->sft_name;
	int pipes[2];
	posix_spawn_file_actions_t acts;
	bool ret = false;
	char fd_strs[SFT_MAXFDS][12];
	char *argv[SFT_MAXFDS + 3];
	size_t ai = 0;

	test->sft_parent_fd = -1;

	if (test->sft_pre != NULL && !test->sft_pre(test))
		goto cleanup;

	posix_spawn_pipe_setup(&acts, pipes);

	if (test->sft_setup != NULL && !test->sft_setup(test, &acts)) {
		VERIFY0(posix_spawn_file_actions_destroy(&acts));
		VERIFY0(close(pipes[0]));
		VERIFY0(close(pipes[1]));
		goto cleanup;
	}

	argv[ai++] = posix_spawn_child_path;
	argv[ai++] = "fds";
	for (size_t i = 0; i < test->sft_nfds; i++) {
		(void) snprintf(fd_strs[i], sizeof (fd_strs[i]), "%d",
		    test->sft_fds[i]);
		argv[ai++] = fd_strs[i];
	}
	argv[ai] = NULL;

	if (test->sft_expect_errno != 0) {
		pid_t pid;
		int err;

		err = posix_spawn(&pid, posix_spawn_child_path, &acts, NULL,
		    argv, NULL);

		if (err == 0) {
			siginfo_t sig;

			warnx("TEST FAILED: %s: "
			    "posix_spawn unexpectedly succeeded", desc);
			(void) waitid(P_PID, pid, &sig, WEXITED);
		} else if (err != test->sft_expect_errno) {
			warnx("TEST FAILED: %s: "
			    "posix_spawn returned %s, expected %s",
			    desc, strerrorname_np(err),
			    strerrorname_np(test->sft_expect_errno));
		} else {
			ret = true;
		}
	} else {
		ret = posix_spawn_run_child(desc, posix_spawn_child_path,
		    &acts, NULL, argv);
		if (ret) {
			ret = spawn_verify_fds(desc, pipes[0],
			    test->sft_expected, test->sft_nfds);
		}
	}

	VERIFY0(posix_spawn_file_actions_destroy(&acts));
	VERIFY0(close(pipes[1]));
	VERIFY0(close(pipes[0]));

cleanup:
	if (test->sft_parent_fd >= 0)
		(void) close(test->sft_parent_fd);

	return (ret);
}

/*
 * Generic setup functions for simple single-action tests.
 * Parameters are read from the test struct.
 */
static bool
addopen_setup(spawn_fa_test_t *test, posix_spawn_file_actions_t *acts)
{
	int ret = posix_spawn_file_actions_addopen(acts, test->sft_open_fd,
	    test->sft_open_path, test->sft_open_flags, 0);
	if (ret != 0) {
		warnx("TEST FAILED: %s: addopen failed with %s",
		    test->sft_name, strerrorname_np(ret));
		return (false);
	}
	return (true);
}

static bool
addclose_setup(spawn_fa_test_t *test, posix_spawn_file_actions_t *acts)
{
	int ret = posix_spawn_file_actions_addclose(acts, test->sft_close_fd);
	if (ret != 0) {
		warnx("TEST FAILED: %s: addclose failed with %s",
		    test->sft_name, strerrorname_np(ret));
		return (false);
	}
	return (true);
}

static bool
adddup2_setup(spawn_fa_test_t *test, posix_spawn_file_actions_t *acts)
{
	int ret = posix_spawn_file_actions_adddup2(acts, test->sft_dup2_from,
	    test->sft_dup2_to);
	if (ret != 0) {
		warnx("TEST FAILED: %s: adddup2 failed with %s",
		    test->sft_name, strerrorname_np(ret));
		return (false);
	}
	return (true);
}

/*
 * Custom setup functions for multi-action tests.
 */

/*
 * Open fd 10 then close it - tests that close acts on a previously
 * opened fd.
 */
static bool
close_action_fd_setup(spawn_fa_test_t *test,
    posix_spawn_file_actions_t *acts)
{
	const char *desc = test->sft_name;
	int ret;

	ret = posix_spawn_file_actions_addopen(acts, 10,
	    "/dev/null", O_RDONLY, 0);
	if (ret != 0) {
		warnx("TEST FAILED: %s: addopen failed with %s",
		    desc, strerrorname_np(ret));
		return (false);
	}

	ret = posix_spawn_file_actions_addclose(acts, 10);
	if (ret != 0) {
		warnx("TEST FAILED: %s: addclose failed with %s",
		    desc, strerrorname_np(ret));
		return (false);
	}

	return (true);
}

/*
 * Close a descriptor that is not open, then open fd 10 - tests that the
 * failed close is ignored and later actions still run.
 */
static bool
close_badfd_setup(spawn_fa_test_t *test, posix_spawn_file_actions_t *acts)
{
	const char *desc = test->sft_name;
	int ret;

	ret = posix_spawn_file_actions_addclose(acts, test->sft_close_fd);
	if (ret != 0) {
		warnx("TEST FAILED: %s: addclose failed with %s",
		    desc, strerrorname_np(ret));
		return (false);
	}

	ret = posix_spawn_file_actions_addopen(acts, 10,
	    "/dev/null", O_RDONLY, 0);
	if (ret != 0) {
		warnx("TEST FAILED: %s: addopen failed with %s",
		    desc, strerrorname_np(ret));
		return (false);
	}

	return (true);
}

/*
 * Open fds 10-13, then closefrom(11).
 */
static bool
closefrom_setup(spawn_fa_test_t *test, posix_spawn_file_actions_t *acts)
{
	const char *desc = test->sft_name;
	int ret;

	for (int fd = 10; fd <= 13; fd++) {
		ret = posix_spawn_file_actions_addopen(acts, fd,
		    "/dev/null", O_RDONLY, 0);
		if (ret != 0) {
			warnx("TEST FAILED: %s: addopen(%d) failed with %s",
			    desc, fd, strerrorname_np(ret));
			return (false);
		}
	}

	ret = posix_spawn_file_actions_addclosefrom_np(acts, 11);
	if (ret != 0) {
		warnx("TEST FAILED: %s: addclosefrom_np failed with %s",
		    desc, strerrorname_np(ret));
		return (false);
	}

	return (true);
}

/*
 * closefrom(3) then open fd 10. Verifies file actions execute sequentially.
 */
static bool
closefrom_then_open_setup(spawn_fa_test_t *test,
    posix_spawn_file_actions_t *acts)
{
	const char *desc = test->sft_name;
	int ret;

	ret = posix_spawn_file_actions_addclosefrom_np(acts, 3);
	if (ret != 0) {
		warnx("TEST FAILED: %s: addclosefrom_np failed with %s",
		    desc, strerrorname_np(ret));
		return (false);
	}

	ret = posix_spawn_file_actions_addopen(acts, 10,
	    "/dev/null", O_RDONLY, 0);
	if (ret != 0) {
		warnx("TEST FAILED: %s: addopen failed with %s",
		    desc, strerrorname_np(ret));
		return (false);
	}

	return (true);
}

/*
 * Open fd 10, dup2 10->20, close 10.
 */
static bool
open_dup_close_setup(spawn_fa_test_t *test, posix_spawn_file_actions_t *acts)
{
	const char *desc = test->sft_name;
	int ret;

	ret = posix_spawn_file_actions_addopen(acts, 10,
	    "/dev/null", O_RDONLY, 0);
	if (ret != 0) {
		warnx("TEST FAILED: %s: addopen failed with %s",
		    desc, strerrorname_np(ret));
		return (false);
	}

	ret = posix_spawn_file_actions_adddup2(acts, 10, 20);
	if (ret != 0) {
		warnx("TEST FAILED: %s: adddup2 failed with %s",
		    desc, strerrorname_np(ret));
		return (false);
	}

	ret = posix_spawn_file_actions_addclose(acts, 10);
	if (ret != 0) {
		warnx("TEST FAILED: %s: addclose failed with %s",
		    desc, strerrorname_np(ret));
		return (false);
	}

	return (true);
}

/*
 * Multiple opens on different fds in sequence.
 */
static bool
multi_open_setup(spawn_fa_test_t *test, posix_spawn_file_actions_t *acts)
{
	const char *desc = test->sft_name;
	int ret;

	ret = posix_spawn_file_actions_addopen(acts, 10, "/dev/null",
	    O_RDONLY, 0);
	if (ret != 0) {
		warnx("TEST FAILED: %s: addopen(10) failed with %s",
		    desc, strerrorname_np(ret));
		return (false);
	}

	ret = posix_spawn_file_actions_addopen(acts, 11, "/dev/null",
	    O_WRONLY, 0);
	if (ret != 0) {
		warnx("TEST FAILED: %s: addopen(11) failed with %s",
		    desc, strerrorname_np(ret));
		return (false);
	}

	ret = posix_spawn_file_actions_addopen(acts, 12, "/dev/null",
	    O_RDWR, 0);
	if (ret != 0) {
		warnx("TEST FAILED: %s: addopen(12) failed with %s",
		    desc, strerrorname_np(ret));
		return (false);
	}

	return (true);
}

/*
 * Pre-test helpers for tests that exercise FD_CLOFORK and FD_CLOEXEC.
 *
 * These open a descriptor in the parent (with the requested flags) before the
 * file actions are added so that the descriptor can be referenced by the file
 * actions and/or checked in the spawned child. The opened descriptors are
 * closed by the framework once the test has run.
 */
static bool
spawn_open_parent_fd(spawn_fa_test_t *test, int fdflags)
{
	int fd = open("/dev/null", O_RDONLY);

	if (fd < 0) {
		warnx("INTERNAL TEST ERROR: %s: open /dev/null failed: %s",
		    test->sft_name, strerrorname_np(errno));
		return (false);
	}

	if (fdflags != 0 && fcntl(fd, F_SETFD, fdflags) != 0) {
		warnx("INTERNAL TEST ERROR: %s: F_SETFD failed: %s",
		    test->sft_name, strerrorname_np(errno));
		(void) close(fd);
		return (false);
	}

	test->sft_parent_fd = fd;
	return (true);
}

/*
 * Configure the test to verify that an FD_CLOFORK descriptor in the parent
 * is not present in the spawned child.
 */
static bool
clofork_present_pre(spawn_fa_test_t *test)
{
	if (!spawn_open_parent_fd(test, FD_CLOFORK))
		return (false);

	test->sft_fds[0] = test->sft_parent_fd;
	test->sft_expected[0].srf_fd = test->sft_parent_fd;
	return (true);
}

/*
 * Configure the test to verify that an FD_CLOEXEC descriptor in the parent
 * is not present in the spawned child once the new program image has been
 * loaded.
 */
static bool
cloexec_present_pre(spawn_fa_test_t *test)
{
	if (!spawn_open_parent_fd(test, FD_CLOEXEC))
		return (false);

	test->sft_fds[0] = test->sft_parent_fd;
	test->sft_expected[0].srf_fd = test->sft_parent_fd;
	return (true);
}

/*
 * Open an FD_CLOFORK descriptor in the parent and configure the test's
 * adddup2 setup to use it as the source. The descriptor is closed at fork
 * time, so the file action is expected to fail with EBADF.
 */
static bool
clofork_dup_action_pre(spawn_fa_test_t *test)
{
	if (!spawn_open_parent_fd(test, FD_CLOFORK))
		return (false);

	test->sft_dup2_from = test->sft_parent_fd;
	return (true);
}

/*
 * Open an FD_CLOEXEC descriptor in the parent and configure the test's
 * adddup2 setup to use it as the source. The duplicate does not inherit
 * FD_CLOEXEC and is expected to persist past exec.
 */
static bool
cloexec_dup_action_pre(spawn_fa_test_t *test)
{
	if (!spawn_open_parent_fd(test, FD_CLOEXEC))
		return (false);

	test->sft_dup2_from = test->sft_parent_fd;
	test->sft_fds[0] = test->sft_parent_fd;
	test->sft_expected[0].srf_fd = test->sft_parent_fd;
	return (true);
}

static spawn_fa_test_t tests[] = {
	/* addopen tests */
	{ .sft_name = "addopen /dev/null O_RDONLY on fd 10",
	    .sft_setup = addopen_setup,
	    .sft_nfds = 1, .sft_fds = { 10 },
	    .sft_expected = {
		{ .srf_fd = 10, .srf_open = 1, .srf_flags = O_RDONLY } },
	    .sft_open_fd = 10, .sft_open_path = "/dev/null",
	    .sft_open_flags = O_RDONLY },
	{ .sft_name = "addopen /dev/null O_WRONLY on fd 11",
	    .sft_setup = addopen_setup,
	    .sft_nfds = 1, .sft_fds = { 11 },
	    .sft_expected = {
		{ .srf_fd = 11, .srf_open = 1, .srf_flags = O_WRONLY } },
	    .sft_open_fd = 11, .sft_open_path = "/dev/null",
	    .sft_open_flags = O_WRONLY },
	{ .sft_name = "addopen /dev/null O_RDWR on fd 12",
	    .sft_setup = addopen_setup,
	    .sft_nfds = 1, .sft_fds = { 12 },
	    .sft_expected = {
		{ .srf_fd = 12, .srf_open = 1, .srf_flags = O_RDWR } },
	    .sft_open_fd = 12, .sft_open_path = "/dev/null",
	    .sft_open_flags = O_RDWR },
	{ .sft_name = "addopen onto STDIN_FILENO (replace stdin)",
	    .sft_setup = addopen_setup,
	    .sft_nfds = 1, .sft_fds = { STDIN_FILENO },
	    .sft_expected = {
		{ .srf_fd = 0, .srf_open = 1, .srf_flags = O_RDWR } },
	    .sft_open_fd = STDIN_FILENO, .sft_open_path = "/dev/null",
	    .sft_open_flags = O_RDWR },
	{ .sft_name = "addopen /dev/null on high fd (50)",
	    .sft_setup = addopen_setup,
	    .sft_nfds = 1, .sft_fds = { 50 },
	    .sft_expected = {
		{ .srf_fd = 50, .srf_open = 1, .srf_flags = O_RDONLY } },
	    .sft_open_fd = 50, .sft_open_path = "/dev/null",
	    .sft_open_flags = O_RDONLY },

	/* addclose tests */
	{ .sft_name = "addclose fd opened by prior action",
	    .sft_setup = close_action_fd_setup,
	    .sft_nfds = 1, .sft_fds = { 10 },
	    .sft_expected = {
		{ .srf_fd = 10, .srf_open = 0 } } },
	{ .sft_name = "addclose STDIN_FILENO",
	    .sft_setup = addclose_setup,
	    .sft_nfds = 1, .sft_fds = { STDIN_FILENO },
	    .sft_expected = {
		{ .srf_fd = 0, .srf_open = 0 } },
	    .sft_close_fd = STDIN_FILENO },

	/* adddup2 tests */
	{ .sft_name = "adddup2 STDOUT to fd 20",
	    .sft_setup = adddup2_setup,
	    .sft_nfds = 1, .sft_fds = { 20 },
	    .sft_expected = {
		{ .srf_fd = 20, .srf_open = 1, .srf_flags = O_RDWR } },
	    .sft_dup2_from = STDOUT_FILENO, .sft_dup2_to = 20 },
	{ .sft_name = "adddup2 to self (fd 0 -> fd 0)",
	    .sft_setup = adddup2_setup,
	    .sft_nfds = 1, .sft_fds = { STDIN_FILENO },
	    .sft_expected = {
		{ .srf_fd = 0, .srf_open = 1, .srf_flags = O_RDONLY } },
	    .sft_dup2_from = STDIN_FILENO, .sft_dup2_to = STDIN_FILENO },

	/* addclosefrom_np tests */
	{ .sft_name = "addclosefrom_np(11) with fds 10-13",
	    .sft_setup = closefrom_setup,
	    .sft_nfds = 4, .sft_fds = { 10, 11, 12, 13 },
	    .sft_expected = {
		{ .srf_fd = 10, .srf_open = 1, .srf_flags = O_RDONLY },
		{ .srf_fd = 11, .srf_open = 0 },
		{ .srf_fd = 12, .srf_open = 0 },
		{ .srf_fd = 13, .srf_open = 0 } } },
	{ .sft_name = "closefrom(3) then open fd 10",
	    .sft_setup = closefrom_then_open_setup,
	    .sft_nfds = 1, .sft_fds = { 10 },
	    .sft_expected = {
		{ .srf_fd = 10, .srf_open = 1, .srf_flags = O_RDONLY } } },

	/* Composition tests */
	{ .sft_name = "open fd 10, dup2 10->20, close 10",
	    .sft_setup = open_dup_close_setup,
	    .sft_nfds = 2, .sft_fds = { 10, 20 },
	    .sft_expected = {
		{ .srf_fd = 10, .srf_open = 0 },
		{ .srf_fd = 20, .srf_open = 1, .srf_flags = O_RDONLY } } },
	{ .sft_name = "multiple opens on fds 10, 11, 12",
	    .sft_setup = multi_open_setup,
	    .sft_nfds = 3, .sft_fds = { 10, 11, 12 },
	    .sft_expected = {
		{ .srf_fd = 10, .srf_open = 1, .srf_flags = O_RDONLY },
		{ .srf_fd = 11, .srf_open = 1, .srf_flags = O_WRONLY },
		{ .srf_fd = 12, .srf_open = 1, .srf_flags = O_RDWR } } },

	/* FD_CLOFORK / FD_CLOEXEC interaction tests */
	{ .sft_name = "FD_CLOFORK descriptor not inherited by child",
	    .sft_pre = clofork_present_pre,
	    .sft_nfds = 1, .sft_fds = { -1 },
	    .sft_expected = {
		{ .srf_fd = -1, .srf_open = 0 } } },
	{ .sft_name = "FD_CLOEXEC descriptor not inherited by child",
	    .sft_pre = cloexec_present_pre,
	    .sft_nfds = 1, .sft_fds = { -1 },
	    .sft_expected = {
		{ .srf_fd = -1, .srf_open = 0 } } },
	{ .sft_name = "adddup2 of FD_CLOFORK fd fails with EBADF",
	    .sft_pre = clofork_dup_action_pre,
	    .sft_setup = adddup2_setup,
	    .sft_dup2_from = -1, .sft_dup2_to = 20,
	    .sft_expect_errno = EBADF },
	{ .sft_name = "adddup2 of FD_CLOEXEC fd produces persistent fd",
	    .sft_pre = cloexec_dup_action_pre,
	    .sft_setup = adddup2_setup,
	    .sft_dup2_from = -1, .sft_dup2_to = 20,
	    .sft_nfds = 2, .sft_fds = { -1, 20 },
	    .sft_expected = {
		{ .srf_fd = -1, .srf_open = 0 },
		{ .srf_fd = 20, .srf_open = 1, .srf_flags = O_RDONLY } } },

	/*
	 * A file action whose open fails must abort the spawn with that
	 * errno rather than treating the error as an opened descriptor.
	 */
	{ .sft_name = "addopen of nonexistent path fails with ENOENT",
	    .sft_setup = addopen_setup,
	    .sft_open_fd = 10,
	    .sft_open_path = "/devices/nonexistent/posix_spawn_test",
	    .sft_open_flags = O_RDONLY,
	    .sft_expect_errno = ENOENT },
	{ .sft_name = "addopen onto fd 2 of nonexistent path fails ENOENT",
	    .sft_setup = addopen_setup,
	    .sft_open_fd = 2,
	    .sft_open_path = "/devices/nonexistent/posix_spawn_test",
	    .sft_open_flags = O_RDONLY,
	    .sft_expect_errno = ENOENT },

	/*
	 * A descriptor too large to fit in the table is validated when the
	 * action runs, not when it is added. open and dup2 actions fail
	 * the spawn with EBADF. A close action on a descriptor that is not
	 * open is not an error and the spawn succeeds.
	 */
	{ .sft_name = "addopen onto INT32_MAX fails with EBADF",
	    .sft_setup = addopen_setup,
	    .sft_open_fd = INT32_MAX, .sft_open_path = "/dev/null",
	    .sft_open_flags = O_RDONLY,
	    .sft_expect_errno = EBADF },
	{ .sft_name = "adddup2 from INT32_MAX fails with EBADF",
	    .sft_setup = adddup2_setup,
	    .sft_dup2_from = INT32_MAX, .sft_dup2_to = 20,
	    .sft_expect_errno = EBADF },
	{ .sft_name = "adddup2 to INT32_MAX fails with EBADF",
	    .sft_setup = adddup2_setup,
	    .sft_dup2_from = STDOUT_FILENO, .sft_dup2_to = INT32_MAX,
	    .sft_expect_errno = EBADF },
	{ .sft_name = "addclose of INT32_MAX (not open) is ignored",
	    .sft_setup = close_badfd_setup,
	    .sft_nfds = 1, .sft_fds = { 10 },
	    .sft_expected = {
		{ .srf_fd = 10, .srf_open = 1, .srf_flags = O_RDONLY } },
	    .sft_close_fd = INT32_MAX },
};

int
main(void)
{
	const char *helpers[] = { POSIX_SPAWN_CHILD_HELPERS };
	int ret = EXIT_SUCCESS;

	for (size_t h = 0; h < ARRAY_SIZE(helpers); h++) {
		posix_spawn_find_helper(posix_spawn_child_path,
		    sizeof (posix_spawn_child_path), helpers[h]);
		(void) printf("--- child helper: %s ---\n", helpers[h]);

		for (size_t i = 0; i < ARRAY_SIZE(tests); i++) {
			if (spawn_test_fds(&tests[i])) {
				(void) printf("TEST PASSED: %s\n",
				    tests[i].sft_name);
			} else {
				ret = EXIT_FAILURE;
			}
		}
	}

	if (ret == EXIT_SUCCESS)
		(void) printf("All tests passed successfully!\n");

	return (ret);
}
