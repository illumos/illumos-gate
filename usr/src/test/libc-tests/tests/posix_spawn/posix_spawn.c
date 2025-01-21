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
 * Copyright 2025 Oxide Computer Company
 */

/*
 * Various tests for posix_spawn(3C). Currently this mostly focuses on
 * functionality added in POSIX 2024 which relates to SETSID and changing
 * directories.
 */

#include <err.h>
#include <stdlib.h>
#include <spawn.h>
#include <stdio.h>
#include <stdbool.h>
#include <unistd.h>
#include <sys/sysmacros.h>
#include <sys/debug.h>
#include <wait.h>
#include <string.h>
#include <fcntl.h>
#include <limits.h>
#include <errno.h>
#include <libgen.h>
#include <inttypes.h>

/*
 * This isn't const so we can refer to it in the argv arrays.
 */
static char *spawn_pwd = "/usr/bin/pwd";
static char spawn_getsid[PATH_MAX];

/*
 * This is an arbitrary fd that we believe will be okay to use in fchdir tests
 * to overwrite.
 */
#define	SPAWN_FD	23

typedef struct spawn_dir_test {
	const char *sdt_desc;
	bool sdt_pass;
	const char *sdt_pwd;
	const char *sdt_dirs[16];
} spawn_dir_test_t;

static const spawn_dir_test_t spawn_dir_tests[] = {
	{
		.sdt_desc = "no chdir",
		.sdt_pass = true,
		.sdt_pwd = "/var/tmp"
	}, {
		.sdt_desc = "absolute path: /etc",
		.sdt_pass = true,
		.sdt_pwd = "/etc",
		.sdt_dirs = { "/etc" }
	}, {
		.sdt_desc = "multiple absolute paths (1)",
		.sdt_pass = true,
		.sdt_pwd = "/dev/net",
		.sdt_dirs = { "/etc", "/dev/net" }
	}, {
		.sdt_desc = "multiple absolute paths (2)",
		.sdt_pass = true,
		.sdt_pwd = "/var/svc",
		.sdt_dirs = { "/proc/self", "/var/svc" }
	}, {
		.sdt_desc = "single relative path (1)",
		.sdt_pass = true,
		.sdt_pwd = "/var/tmp",
		.sdt_dirs = { "." },
	}, {
		.sdt_desc = "single relative path (2)",
		.sdt_pass = true,
		.sdt_pwd = "/var",
		.sdt_dirs = { ".." },
	}, {
		.sdt_desc = "multiple relative paths (1)",
		.sdt_pass = true,
		.sdt_pwd = "/usr/lib/dtrace",
		.sdt_dirs = { "..", "..", "usr", "lib", "dtrace" },
	}, {
		.sdt_desc = "multiple relative paths (2)",
		.sdt_pass = true,
		.sdt_pwd = "/var/tmp",
		.sdt_dirs = { "..", "tmp" },
	}, {
		.sdt_desc = "mixing absolute and relative paths (1)",
		.sdt_pass = true,
		.sdt_pwd = "/usr/lib/fm/fmd",
		.sdt_dirs = { "..", "/usr/lib/fm", "fmd" },
	}, {
		.sdt_desc = "mixing absolute and relative paths (2)",
		.sdt_pass = true,
		.sdt_pwd = "/usr/bin",
		.sdt_dirs = { "/usr/lib/64", "..", "..", "bin" },
	}, {
		.sdt_desc = "mixing absolute and relative paths (3)",
		.sdt_pass = true,
		.sdt_pwd = "/etc/svc/volatile",
		.sdt_dirs = { "/usr/lib/64", "..", "..", "bin",
		    "/etc/svc/volatile" },
	}, {
		/*
		 * Note, these bad path tests will not be terribly meaningful
		 * for fchdir because the open will fail.
		 */
		.sdt_desc = "bad path 1",
		.sdt_pass = false,
		.sdt_dirs = { "/#error//?*!@#$!asdf/please/don't/exist" }
	}, {
		.sdt_desc = "bad path 2",
		.sdt_pass = false,
		.sdt_dirs = { "/tmp", "\x001\x002\x003\x004\x003\x042" }
	}
};

typedef struct spawn_flags_test {
	const char *sft_desc;
	int sft_ret;
	short sft_flags;
} spawn_flags_test_t;

static const spawn_flags_test_t spawn_flags_tests[] = {
	{
		.sft_desc = "no flags",
		.sft_ret = 0,
		.sft_flags = 0
	}, {
		.sft_desc = "flag SETPGROUP",
		.sft_ret = 0,
		.sft_flags = POSIX_SPAWN_SETPGROUP
	}, {
		.sft_desc = "flag SETSID",
		.sft_ret = 0,
		.sft_flags = POSIX_SPAWN_SETSID
	}, {
		.sft_desc = "flags SETSID | SETPGROUP",
		.sft_ret = EPERM,
		.sft_flags = POSIX_SPAWN_SETSID | POSIX_SPAWN_SETPGROUP
	}
};

/*
 * Add standard actions to capture stdout but nothing else.
 */
static void
posix_spawn_setup_fds(posix_spawn_file_actions_t *acts, int pipes[2])
{
	int ret;

	if (pipe2(pipes, O_NONBLOCK) != 0) {
		err(EXIT_FAILURE, "INTERNAL TEST FAILURE: failed to create a "
		    "pipe");
	}

	VERIFY3S(pipes[0], >, STDERR_FILENO);
	VERIFY3S(pipes[1], >, STDERR_FILENO);

	if ((ret = posix_spawn_file_actions_init(acts)) != 0) {
		errc(EXIT_FAILURE, ret, "INTERNAL TEST FAILURE: failed to "
		    "initialize posix_spawn file actions");
	}

	if ((ret = posix_spawn_file_actions_addopen(acts, STDIN_FILENO,
	    "/dev/null", O_RDONLY, 0)) != 0) {
		errc(EXIT_FAILURE, ret, "INTERNAL TEST FAILURE: failed to add "
		    "/dev/null open action");
	}

	if ((ret = posix_spawn_file_actions_adddup2(acts, STDIN_FILENO,
	    STDERR_FILENO)) != 0) {
		errc(EXIT_FAILURE, ret, "INTERNAL TEST FAILURE: failed to add "
		    "stderr dup action");
	}

	if ((ret = posix_spawn_file_actions_adddup2(acts, pipes[1],
	    STDOUT_FILENO)) != 0) {
		errc(EXIT_FAILURE, ret, "INTERNAL TEST FAILURE: failed to add "
		    "stdout dup action");
	}

	if ((ret = posix_spawn_file_actions_addclose(acts, pipes[0])) != 0) {
		errc(EXIT_FAILURE, ret, "INTERNAL TEST FAILURE: failed to add "
		    "pipes[0] close action");
	}

	if ((ret = posix_spawn_file_actions_addclose(acts, pipes[1])) != 0) {
		errc(EXIT_FAILURE, ret, "INTERNAL TEST FAILURE: failed to add "
		    "pipes[1] close action");
	}
}

static bool
posix_spawn_test_one_dir(const spawn_dir_test_t *test, int pipes[2],
    posix_spawn_file_actions_t *acts, const char *desc)
{
	int ret;
	bool bret = false;
	char *const argv[2] = { spawn_pwd, NULL };
	char *const envp[1] = { NULL };
	pid_t pid;
	siginfo_t sig;
	char pwd[PATH_MAX];
	ssize_t pwd_len;

	if ((ret = posix_spawn(&pid, spawn_pwd, acts, NULL, argv, envp)) != 0) {
		if (!test->sdt_pass) {
			(void) printf("TEST PASSED: %s (%s): posix_spawn "
			    "failed as expected\n", test->sdt_desc, desc);
			bret = true;
			goto out;
		} else {
			warnx("TEST FAILED: %s posix_spawn() failed with %s, "
			    "but expected success", test->sdt_desc,
			    strerrorname_np(ret));
			goto out;
		}
	}

	if (waitid(P_PID, pid, &sig, WEXITED) != 0) {
		err(EXIT_FAILURE, "INTERNAL TEST ERROR: %s: failed to wait on "
		    "pid %" _PRIdID ", but posix_spawn executed it",
		    test->sdt_desc, pid);
	}

	if (sig.si_code != CLD_EXITED) {
		warnx("TEST FAILED: %s: child did not successfully exit: "
		    "foud si_code: %d", test->sdt_desc, sig.si_code);
		goto out;
	}

	if (sig.si_status != 0) {
		if (!test->sdt_pass) {
			(void) printf("TEST PASSED: %s (%s): child process "
			    "failed", test->sdt_desc, desc);
			bret = true;
			goto out;
		}

		warnx("TEST FAILED: %s: child exited with status %d, expected "
		    "success", test->sdt_desc, sig.si_status);
		goto out;
	} else if (!test->sdt_pass) {
		warnx("TEST FAILED: %s: child exited successfully, but "
		    "expected failure", test->sdt_desc);
		goto out;
	}

	/*
	 * At this point we know that we have a pwd process that has
	 * successfully exited. We should be able to perform a non-blocking read
	 * from the pipe successfully and get its working directory. pwd(1)
	 * appends a new line. We remove it.
	 */
	pwd[0] = 0;
	pwd_len = read(pipes[0], pwd, sizeof (pwd));
	if (pwd_len < 0) {
		warn("TEST FAILED: %s: failed to read pwd from pipe",
		    test->sdt_desc);
		goto out;
	} else if (pwd_len == 0) {
		warn("TEST FAILED: %s: got zero byte read from pipe?!",
		    test->sdt_desc);
		goto out;
	}
	pwd[pwd_len - 1] = '\0';

	if (strcmp(pwd, test->sdt_pwd) != 0) {
		warnx("TEST FAILED: %s: found pwd '%s', expected '%s'",
		    test->sdt_desc, pwd, test->sdt_pwd);
		goto out;
	}

	(void) printf("TEST PASSED: %s (%s)\n", test->sdt_desc, desc);

	bret = true;
out:
	return (bret);
}

static bool
posix_spawn_test_one_chdir(const spawn_dir_test_t *test)
{
	int ret, pipes[2];
	bool bret = false;
	posix_spawn_file_actions_t acts;

	/*
	 * We set up a pipe to act as stdout so we can capture the output from
	 * pwd. While we could use /proc to try and do this, we prefer this
	 * mechanism.
	 */
	posix_spawn_setup_fds(&acts, pipes);

	for (size_t i = 0; i < ARRAY_SIZE(test->sdt_dirs); i++) {
		if (test->sdt_dirs[i] == NULL)
			break;

		ret = posix_spawn_file_actions_addchdir(&acts,
		    test->sdt_dirs[i]);
		if (ret != 0) {
			warnc(ret, "TEST FAILED: %s: adding path '%s' "
			    "(%zu) failed unexpectedly", test->sdt_desc,
			    test->sdt_dirs[i], i);
			goto out;
		}
	}

	bret = posix_spawn_test_one_dir(test, pipes, &acts, "chdir");
out:
	VERIFY0(posix_spawn_file_actions_destroy(&acts));
	VERIFY0(close(pipes[1]));
	VERIFY0(close(pipes[0]));
	return (bret);
}

static bool
posix_spawn_test_one_fchdir(const spawn_dir_test_t *test)
{
	int ret, pipes[2];
	bool bret = false;
	posix_spawn_file_actions_t acts;

	/*
	 * We set up a pipe to act as stdout so we can capture the output from
	 * pwd. While we could use /proc to try and do this, we prefer this
	 * mechanism.
	 */
	posix_spawn_setup_fds(&acts, pipes);

	/*
	 * For the fchdir tests we go in a loop over these directories opening
	 * an fd, doing an fchdir to it, and then closing it.
	 */
	for (size_t i = 0; i < ARRAY_SIZE(test->sdt_dirs); i++) {
		if (test->sdt_dirs[i] == NULL)
			break;

		ret = posix_spawn_file_actions_addopen(&acts, SPAWN_FD,
		    test->sdt_dirs[i], O_RDONLY | O_DIRECTORY, 0);
		if (ret != 0) {
			warnc(ret, "TEST FAILED: %s: adding open action for "
			    "path '%s' (%zu) failed unexpectedly",
			    test->sdt_desc, test->sdt_dirs[i], i);
			goto out;
		}

		ret = posix_spawn_file_actions_addfchdir(&acts, SPAWN_FD);
		if (ret != 0) {
			warnc(ret, "TEST FAILED: %s: adding fchdir action for "
			    "path '%s' (%zu) failed unexpectedly",
			    test->sdt_desc, test->sdt_dirs[i], i);
			goto out;
		}

		ret = posix_spawn_file_actions_addclose(&acts, SPAWN_FD);
		if (ret != 0) {
			warnc(ret, "TEST FAILED: %s: adding close action for "
			    "path '%s' (%zu) failed unexpectedly",
			    test->sdt_desc, test->sdt_dirs[i], i);
			goto out;
		}
	}

	bret = posix_spawn_test_one_dir(test, pipes, &acts, "fchdir");
out:
	VERIFY0(posix_spawn_file_actions_destroy(&acts));
	VERIFY0(close(pipes[1]));
	VERIFY0(close(pipes[0]));
	return (bret);
}

/*
 * Test a few different bad file actions.
 */
static bool
posix_spawn_test_bad_actions(void)
{
	int ret;
	bool bret = true;
	posix_spawn_file_actions_t acts;

	if ((ret = posix_spawn_file_actions_init(&acts)) != 0) {
		errc(EXIT_FAILURE, ret, "INTERNAL TEST FAILURE: failed to "
		    "initialize posix_spawn file actions");
	}

	if ((ret = posix_spawn_file_actions_addfchdir(&acts, -23)) == 0) {
		warnx("TEST FAILED: addfchdir() with bad fd: expected EBADF, "
		    "but returned successfully");
		bret = false;
	} else if (ret != EBADF) {
		warnx("TEST FAILED: addfchdir with bad fd: failed with %s, "
		    "but expected EBADF", strerrorname_np(ret));
		bret = false;
	} else {
		(void) printf("TEST PASSED: addfchdir() with bad fd: correctly "
		    "got EBADF\n");
	}

	if ((ret = posix_spawn_file_actions_addopen(&acts, -23, "/dev/null",
	    O_RDONLY, 0)) == 0) {
		warnx("TEST FAILED: addopen() with bad fd: expected EBADF, "
		    "but returned successfully");
		bret = false;
	} else if (ret != EBADF) {
		warnx("TEST FAILED: addopen with bad fd: failed with %s, "
		    "but expected EBADF", strerrorname_np(ret));
		bret = false;
	} else {
		(void) printf("TEST PASSED: addopen() with bad fd: correctly "
		    "got EBADF\n");
	}

	if ((ret = posix_spawn_file_actions_addclose(&acts, -23)) == 0) {
		warnx("TEST FAILED: addclose() with bad fd: expected EBADF, "
		    "but returned successfully");
		bret = false;
	} else if (ret != EBADF) {
		warnx("TEST FAILED: addclose with bad fd: failed with %s, "
		    "but expected EBADF", strerrorname_np(ret));
		bret = false;
	} else {
		(void) printf("TEST PASSED: addclose() with bad fd: correctly "
		    "got EBADF\n");
	}

	VERIFY0(posix_spawn_file_actions_destroy(&acts));
	return (bret);
}

/*
 * Verify that if we try to do an fchdir to an invalid fd that everything fails.
 */
static bool
posix_spawn_test_bad_fchdir(void)
{
	int ret, pipes[2];
	bool bret = false;
	posix_spawn_file_actions_t acts;
	spawn_dir_test_t test;

	(void) memset(&test, 0, sizeof (test));
	test.sdt_desc = "fchdir to closed fd";
	test.sdt_pass = false;
	test.sdt_pwd = "/nope";

	/*
	 * We set up a pipe to act as stdout so we can capture the output from
	 * pwd. While we could use /proc to try and do this, we prefer this
	 * mechanism.
	 */
	posix_spawn_setup_fds(&acts, pipes);

	ret = posix_spawn_file_actions_addclose(&acts, SPAWN_FD);
	if (ret != 0) {
		warnc(ret, "TEST FAILED: %s: adding close action failed "
		    "unexpectedly", test.sdt_desc);
		goto out;
	}

	ret = posix_spawn_file_actions_addfchdir(&acts, SPAWN_FD);
	if (ret != 0) {
		warnc(ret, "TEST FAILED: %s: adding close action failed "
		    "unexpectedly", test.sdt_desc);
		goto out;
	}

	bret = posix_spawn_test_one_dir(&test, pipes, &acts, "fchdir");
out:
	VERIFY0(posix_spawn_file_actions_destroy(&acts));
	VERIFY0(close(pipes[1]));
	VERIFY0(close(pipes[0]));
	return (bret);
}


static bool
posix_spawn_test_one_flags(const spawn_flags_test_t *test)
{
	int ret, pipes[2];
	bool bret = true;
	char *const argv[2] = { spawn_getsid, NULL };
	char *const envp[1] = { NULL };
	pid_t buf[2];
	posix_spawn_file_actions_t acts;
	posix_spawnattr_t attr;
	short flags;
	pid_t pid, exp_sid, exp_pgid;
	siginfo_t sig;
	ssize_t buf_len;
	const char *sid_desc, *pgid_desc;

	posix_spawn_setup_fds(&acts, pipes);

	if ((ret = posix_spawnattr_init(&attr)) != 0) {
		errc(EXIT_FAILURE, ret, "INTERNAL TEST FAILURE: failed to "
		    "initialize posix_spawn attributes");
	}

	VERIFY0(posix_spawnattr_getflags(&attr, &flags));
	if (flags != 0) {
		warnx("TEST FAILED: %s: initial flags are not zero, found 0x%x",
		    test->sft_desc, flags);
		bret = false;
	}
	VERIFY0(posix_spawnattr_setflags(&attr, test->sft_flags));
	VERIFY0(posix_spawnattr_getflags(&attr, &flags));
	if (flags != test->sft_flags) {
		warnx("TEST FAILED: %s: flags are don't match what we set: "
		    "found 0x%x, expected 0x%x", test->sft_desc, flags,
		    test->sft_flags);
		bret = false;
	}

	ret = posix_spawn(&pid, spawn_getsid, &acts, &attr, argv, envp);
	if (ret != test->sft_ret) {
		if (test->sft_ret == 0) {
			warnx("TEST FAILED: %s posix_spawn() failed with %s, "
			    "but expected success", test->sft_desc,
			    strerrorname_np(ret));
		} else {
			warnx("TEST FAILED: %s posix_spawn() failed with %s, "
			    "but expected %s", test->sft_desc,
			    strerrorname_np(ret),
			    strerrorname_np(test->sft_ret));
		}
		bret = false;
		goto out;
	}

	if (test->sft_ret != 0) {
		(void) printf("TEST PASSED: %s: posix_spawn() failed correctly "
		    "with %s\n", test->sft_desc, strerrorname_np(ret));
		goto out;
	}

	if (waitid(P_PID, pid, &sig, WEXITED) != 0) {
		err(EXIT_FAILURE, "INTERNAL TEST ERROR: %s: failed to wait on "
		    "pid %" _PRIdID ", but posix_spawn executed it",
		    test->sft_desc, pid);
	}

	if (sig.si_code != CLD_EXITED) {
		warnx("TEST FAILED: %s: child did not successfully exit: "
		    "foud si_code: %d", test->sft_desc, sig.si_code);
		bret = false;
		goto out;
	}

	if (sig.si_status != 0) {
		warnx("TEST FAILED: %s: child exited with status %d, expected "
		    "success", test->sft_desc, sig.si_status);
		bret = false;
		goto out;
	}

	/*
	 * The getsid.64 process writes as binary data the results of getsid(2)
	 * and getpgid(2) to our pipe. We should be able to read all of this in
	 * one swoop.
	 */
	buf_len = read(pipes[0], buf, sizeof (buf));
	if (buf_len < 0) {
		warn("TEST FAILED: %s: failed to read IDs from pipe",
		    test->sft_desc);
		bret = false;
		goto out;
	} else if (buf_len == 0) {
		warn("TEST FAILED: %s: got zero byte read from pipe?!",
		    test->sft_desc);
		bret = false;
		goto out;
	}

	/*
	 * Now we need to check the various process group and session IDs. We
	 * expect the following values:
	 *
	 * If the SETSID flag was set then the session ID should match the
	 * child's pid. Otherwise it should match our value.
	 *
	 * If the SETSID or SETPGROUP flag was set then the process group ID
	 * should match the child's pid. Otherwise it should match our value.
	 */
	if ((test->sft_flags & POSIX_SPAWN_SETSID) != 0) {
		exp_sid = pid;
		sid_desc = "child's ID";
	} else {
		exp_sid = getsid(0);
		sid_desc = "test's SID";
	}

	if ((test->sft_flags & (POSIX_SPAWN_SETSID |
	    POSIX_SPAWN_SETPGROUP)) != 0) {
		exp_pgid = pid;
		pgid_desc = "child's ID";
	} else {
		exp_pgid = getpgid(0);
		pgid_desc = "test's PGID";
	}

	if (buf[0] != exp_sid) {
		warnx("TEST FAILED: %s: session ID mismatch: expected 0x%"
		    _PRIxID " (%s), found 0x%" _PRIxID, test->sft_desc, exp_sid,
		    sid_desc, buf[0]);
		bret = false;
	}

	if (buf[1] != exp_pgid) {
		warnx("TEST FAILED: %s: process group ID mismatch: expected "
		    "0x%" _PRIxID " (%s), found 0x%" _PRIxID, test->sft_desc,
		    exp_pgid, pgid_desc, buf[1]);
		bret = false;
	}

	if (bret) {
		(void) printf("TEST PASSED: %s\n", test->sft_desc);
	}

out:
	VERIFY0(posix_spawnattr_destroy(&attr));
	VERIFY0(posix_spawn_file_actions_destroy(&acts));
	VERIFY0(close(pipes[1]));
	VERIFY0(close(pipes[0]));
	return (bret);
}

/*
 * Set up paths that are dependent on where our binary is found.
 */
static void
posix_spawn_test_paths(void)
{
	ssize_t ret;
	char origin[PATH_MAX];

	ret = readlink("/proc/self/path/a.out", origin, PATH_MAX - 1);
	if (ret < 0) {
		err(EXIT_FAILURE, "INTERNAL TEST FAILURE: failed to read "
		    "a.out path");
	}

	origin[ret] = '\0';
	if (snprintf(spawn_getsid, sizeof (spawn_getsid), "%s/getsid.64",
	    dirname(origin)) >= sizeof (spawn_getsid)) {
		errx(EXIT_FAILURE, "INTERNAL TEST FAILURE: failed to assemble "
		    "getsid.64 path");
	}

	if (access(spawn_getsid, X_OK) != 0) {
		err(EXIT_FAILURE, "INTERNAL TEST FAILURE: failed to access %s",
		    spawn_getsid);
	}
}

int
main(void)
{
	int ret = EXIT_SUCCESS;

	/*
	 * Because this test wants to rely on a known starting directory, we're
	 * going to chdir into /var/tmp at the start of this.
	 */
	if (chdir("/var/tmp") != 0) {
		err(EXIT_FAILURE, "INTERNAL TEST ERROR: failed to cd into "
		    "/var/tmp");
	}

	posix_spawn_test_paths();

	for (size_t i = 0; i < ARRAY_SIZE(spawn_dir_tests); i++) {
		if (!posix_spawn_test_one_chdir(&spawn_dir_tests[i]))
			ret = EXIT_FAILURE;

		if (!posix_spawn_test_one_fchdir(&spawn_dir_tests[i]))
			ret = EXIT_FAILURE;
	}

	if (!posix_spawn_test_bad_actions()) {
		ret = EXIT_FAILURE;
	}

	if (!posix_spawn_test_bad_fchdir()) {
		ret = EXIT_FAILURE;
	}

	for (size_t i = 0; i < ARRAY_SIZE(spawn_flags_tests); i++) {
		if (!posix_spawn_test_one_flags(&spawn_flags_tests[i]))
			ret = EXIT_FAILURE;
	}

	if (ret == EXIT_SUCCESS) {
		(void) printf("All tests passed successfully!\n");
	}

	return (ret);
}
