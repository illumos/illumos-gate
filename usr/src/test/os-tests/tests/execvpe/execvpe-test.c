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
 * This tests various behaviors of execvpe to try and verify that it is working
 * as expected.
 */

#include <stdlib.h>
#include <err.h>
#include <unistd.h>
#include <stdbool.h>
#include <errno.h>
#include <sys/sysmacros.h>
#include <sys/fork.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <stdio.h>

typedef struct {
	const char *et_desc;
	const char *et_prog;
	const char *et_path;
	bool et_pass;
	int et_errno;
} execvpe_test_t;

static const execvpe_test_t execvpe_tests[] = {
	{ .et_desc = "execute ls on default path", .et_prog = "ls",
	    .et_path = NULL, .et_pass = true },
	{ .et_desc = "execute ls on specified path (1)", .et_prog = "ls",
	    .et_path = "/usr/bin", .et_pass = true },
	{ .et_desc = "execute ls on specified path (2)", .et_prog = "ls",
	    .et_path = "/usr/lib/fm/topo/maps:/enoent:/usr/bin",
	    .et_pass = true },
	{ .et_desc = "fail to find ls on path", .et_prog = "ls",
	    .et_path = "/usr/lib/mdb/raw", .et_pass = false,
	    .et_errno = ENOENT },
	{ .et_desc = "fail to find program on default path",
	    .et_prog = "()theroadgoeseveronandon?!@#$%,downfromthedoor",
	    .et_path = NULL, .et_pass = false, .et_errno = ENOENT },
	{ .et_desc = "shell executes script without #!",
	    .et_prog = "execvpe-script",
	    .et_path = "/opt/os-tests/tests/execvpe", .et_pass = true },
	{ .et_desc = "properly fail with non-executable file",
	    .et_prog = "execvpe-noperm",
	    .et_path = "/opt/os-tests/tests/execvpe", .et_pass = false,
	    .et_errno = EACCES },
	{ .et_desc = "absolute path works if not in PATH",
	    .et_prog = "/usr/bin/true", .et_path = "/usr/lib", .et_pass = true }
};

static bool
execvpe_test_one(const execvpe_test_t *test)
{
	pid_t pid, wpid;
	int stat;
	const char *envp[4];
	const char *argv[2];

	if (test->et_path != NULL) {
		if (setenv("PATH", test->et_path, 1) != 0) {
			err(EXIT_FAILURE, "TEST FAILED: %s: fatal error: "
			    "failed to set PATH", test->et_desc);
		}
	} else {
		if (unsetenv("PATH") != 0) {
			err(EXIT_FAILURE, "TEST FAILED: %s: fatal error: "
			    "failed to unset PATH", test->et_desc);
		}
	}

	envp[0] = "PATH=/this/should/not/interfere:/with/the/test";
	envp[1] = "EXECVPE_TEST=Keep it secret, keep it safe!";
	envp[2] = "WHOAMI=gandalf";
	envp[3] = NULL;

	argv[0] = test->et_prog;
	argv[1] = NULL;

	pid = forkx(FORK_NOSIGCHLD | FORK_WAITPID);
	if (pid == 0) {
		int ret = EXIT_SUCCESS, e;
		(void) execvpe(test->et_prog, (char * const *)argv,
		    (char *const *)envp);
		e = errno;
		if (test->et_pass) {
			warnc(e, "TEST FAILED: %s: expected execvpe success, "
			    "but no such luck", test->et_desc);
			ret = EXIT_FAILURE;
		} else if (test->et_errno != e) {
			warnx("TEST FAILED: %s: execvpe failed with errno %d, "
			    "expected %d", test->et_desc, e, test->et_errno);
			ret = EXIT_FAILURE;
		}
		_exit(ret);
	}

	wpid = waitpid(pid, &stat, 0);
	if (wpid != pid) {
		errx(EXIT_FAILURE, "TEST FAILED: %s: encountered fatal error "
		    "waitpid returned wrong pid: %" _PRIdID ", expected "
		    "%" _PRIdID, test->et_desc, wpid, pid);
	}

	if (stat == EXIT_SUCCESS) {
		(void) printf("TEST PASSED: %s\n", test->et_desc);
		return (true);
	}

	return (false);
}

int
main(void)
{
	int ret = EXIT_SUCCESS;

	for (size_t i = 0; i < ARRAY_SIZE(execvpe_tests); i++) {
		if (!execvpe_test_one(&execvpe_tests[i]))
			ret = EXIT_FAILURE;
	}

	if (ret == EXIT_SUCCESS) {
		(void) printf("All tests passed successfully!\n");
	}

	return (ret);
}
