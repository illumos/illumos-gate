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
 * Tests for posix_spawn_pipe_np(3C), which spawns "sh -c <cmd>" and
 * returns a pipe fd for reading from or writing to the child.
 */

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <spawn.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <wait.h>
#include <sys/sysmacros.h>
#include <sys/debug.h>

#include "posix_spawn_common.h"

typedef struct spawn_pipe_test {
	const char	*spt_name;
	bool		(*spt_func)(struct spawn_pipe_test *);
} spawn_pipe_test_t;

/*
 * Read from a child process: "sh -c echo hello". Verify we get "hello\n".
 */
static bool
read_from_child_test(spawn_pipe_test_t *test)
{
	const char *desc = test->spt_name;
	posix_spawn_file_actions_t fact;
	posix_spawnattr_t attr;
	pid_t pid;
	int fd, ret;
	char buf[64];
	ssize_t n;
	siginfo_t sig;

	VERIFY0(posix_spawn_file_actions_init(&fact));
	VERIFY0(posix_spawnattr_init(&attr));

	ret = posix_spawn_pipe_np(&pid, &fd, "echo hello", B_FALSE,
	    &fact, &attr);
	if (ret != 0) {
		warnx("TEST FAILED: %s: posix_spawn_pipe_np failed with %s",
		    desc, strerrorname_np(ret));
		VERIFY0(posix_spawn_file_actions_destroy(&fact));
		VERIFY0(posix_spawnattr_destroy(&attr));
		return (false);
	}

	n = read(fd, buf, sizeof (buf) - 1);
	(void) close(fd);

	if (waitid(P_PID, pid, &sig, WEXITED) != 0)
		err(EXIT_FAILURE, "INTERNAL TEST ERROR: %s: waitid", desc);

	if (n < 0) {
		warn("TEST FAILED: %s: read from pipe failed", desc);
		VERIFY0(posix_spawn_file_actions_destroy(&fact));
		VERIFY0(posix_spawnattr_destroy(&attr));
		return (false);
	}

	buf[n] = '\0';

	if (strcmp(buf, "hello\n") != 0) {
		warnx("TEST FAILED: %s: expected 'hello\\n', got '%s'",
		    desc, buf);
		VERIFY0(posix_spawn_file_actions_destroy(&fact));
		VERIFY0(posix_spawnattr_destroy(&attr));
		return (false);
	}

	VERIFY0(posix_spawn_file_actions_destroy(&fact));
	VERIFY0(posix_spawnattr_destroy(&attr));

	return (sig.si_code == CLD_EXITED && sig.si_status == 0);
}

/*
 * Write to a child process: pipe data to "cat", capture its output via a
 * temporary file. Verify the data round-trips.
 */
static bool
write_to_child_test(spawn_pipe_test_t *test)
{
	const char *desc = test->spt_name;
	posix_spawn_file_actions_t fact;
	posix_spawnattr_t attr;
	pid_t pid;
	int fd, ret;
	siginfo_t sig;
	bool bret = true;
	char tmpfile[] = "/tmp/posix_spawn_pipe_np.XXXXXX";
	char cmd[PATH_MAX];
	int tmpfd;
	char buf[64];
	ssize_t n;
	const char *msg = "test data\n";

	tmpfd = mkstemp(tmpfile);
	if (tmpfd == -1) {
		warn("TEST FAILED: %s: mkstemp failed", desc);
		return (false);
	}
	(void) close(tmpfd);

	if (snprintf(cmd, sizeof (cmd), "cat > %s", tmpfile) >=
	    sizeof (cmd)) {
		warnx("TEST FAILED: %s: command too long", desc);
		return (false);
	}

	VERIFY0(posix_spawn_file_actions_init(&fact));
	VERIFY0(posix_spawnattr_init(&attr));

	ret = posix_spawn_pipe_np(&pid, &fd, cmd, B_TRUE, &fact, &attr);
	if (ret != 0) {
		warnx("TEST FAILED: %s: posix_spawn_pipe_np failed with %s",
		    desc, strerrorname_np(ret));
		bret = false;
		goto out;
	}

	if (write(fd, msg, strlen(msg)) != (ssize_t)strlen(msg)) {
		warn("TEST FAILED: %s: write to pipe failed", desc);
		bret = false;
	}
	(void) close(fd);

	if (waitid(P_PID, pid, &sig, WEXITED) != 0)
		err(EXIT_FAILURE, "INTERNAL TEST ERROR: %s: waitid", desc);

	if (sig.si_code != CLD_EXITED || sig.si_status != 0) {
		warnx("TEST FAILED: %s: child did not exit cleanly", desc);
		bret = false;
		goto out;
	}

	/* Read back from the temporary file and verify. */
	tmpfd = open(tmpfile, O_RDONLY);
	if (tmpfd == -1) {
		warn("TEST FAILED: %s: open(%s) failed", desc, tmpfile);
		bret = false;
		goto out;
	}

	n = read(tmpfd, buf, sizeof (buf) - 1);
	(void) close(tmpfd);

	if (n < 0) {
		warn("TEST FAILED: %s: read from tmpfile failed", desc);
		bret = false;
		goto out;
	}

	buf[n] = '\0';
	if (strcmp(buf, msg) != 0) {
		warnx("TEST FAILED: %s: expected '%s', got '%s'",
		    desc, msg, buf);
		bret = false;
	}

out:
	(void) unlink(tmpfile);
	VERIFY0(posix_spawn_file_actions_destroy(&fact));
	VERIFY0(posix_spawnattr_destroy(&attr));

	return (bret);
}

/*
 * Error case: spawn a command that doesn't exist.
 */
static bool
bad_cmd_test(spawn_pipe_test_t *test)
{
	const char *desc = test->spt_name;
	posix_spawn_file_actions_t fact;
	posix_spawnattr_t attr;
	pid_t pid;
	int fd, ret;
	siginfo_t sig;

	VERIFY0(posix_spawn_file_actions_init(&fact));
	VERIFY0(posix_spawnattr_init(&attr));

	/*
	 * posix_spawn_pipe_np spawns "sh -c <cmd>", so even a bad command
	 * will successfully spawn sh. The shell itself will report the error
	 * via a non-zero exit status.
	 */
	ret = posix_spawn_pipe_np(&pid, &fd, "/devices/nonexistent/cmd",
	    B_FALSE, &fact, &attr);
	if (ret != 0) {
		warnx("TEST FAILED: %s: posix_spawn_pipe_np failed with %s, "
		    "expected success (sh spawns)", desc, strerrorname_np(ret));
		VERIFY0(posix_spawn_file_actions_destroy(&fact));
		VERIFY0(posix_spawnattr_destroy(&attr));
		return (false);
	}

	(void) close(fd);

	if (waitid(P_PID, pid, &sig, WEXITED) != 0)
		err(EXIT_FAILURE, "INTERNAL TEST ERROR: %s: waitid", desc);

	VERIFY0(posix_spawn_file_actions_destroy(&fact));
	VERIFY0(posix_spawnattr_destroy(&attr));

	if (sig.si_code != CLD_EXITED || sig.si_status == 0) {
		warnx("TEST FAILED: %s: expected non-zero exit from shell",
		    desc);
		return (false);
	}

	return (true);
}

static spawn_pipe_test_t tests[] = {
	{ .spt_name = "pipe_np: read from child (echo)",
	    .spt_func = read_from_child_test },
	{ .spt_name = "pipe_np: write to child (cat)",
	    .spt_func = write_to_child_test },
	{ .spt_name = "pipe_np: bad command exits non-zero",
	    .spt_func = bad_cmd_test },
};

int
main(void)
{
	int ret = EXIT_SUCCESS;

	for (size_t i = 0; i < ARRAY_SIZE(tests); i++) {
		if (tests[i].spt_func(&tests[i]))
			(void) printf("TEST PASSED: %s\n", tests[i].spt_name);
		else
			ret = EXIT_FAILURE;
	}

	if (ret == EXIT_SUCCESS)
		(void) printf("All tests passed successfully!\n");

	return (ret);
}
