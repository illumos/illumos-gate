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
 * Tests for posix_spawnp(3C) PATH resolution and ENOEXEC shell fallback.
 * Each test forks to isolate environment changes from the parent, then uses
 * posix_spawnp in the child.
 */

#include <err.h>
#include <stdlib.h>
#include <spawn.h>
#include <stdio.h>
#include <stdbool.h>
#include <unistd.h>
#include <sys/sysmacros.h>
#include <sys/debug.h>
#include <sys/fork.h>
#include <wait.h>
#include <string.h>
#include <fcntl.h>
#include <limits.h>
#include <sys/stat.h>
#include <errno.h>
#include <libgen.h>

#include "posix_spawn_common.h"

extern char **environ;

/*
 * Directory containing the no-shebang script, used as PATH for spawnp tests.
 */
static char posix_spawn_noshebang_dir[PATH_MAX];

/*
 * Runtime-constructed PATH strings.
 */
static char noexec_dir[PATH_MAX];
static char eacces_path[PATH_MAX * 2];
static char toolong_path[PATH_MAX + 16];
static char toolong_ok_path[PATH_MAX + 32];

typedef struct spawn_path_test spawn_path_test_t;

struct spawn_path_test {
	const char	*spt_desc;
	bool		(*spt_func)(spawn_path_test_t *);
	const char	*spt_file;	/* file arg to posix_spawnp */
	const char	*spt_path;	/* PATH to set, or NULL to unset */
	bool		spt_pass;	/* expect success? */
	int		spt_err;	/* expected errno if !spt_pass */
};

/*
 * Run a single posix_spawnp PATH resolution test inside a forked child
 * process to isolate environment changes.
 */
static bool
path_resolve_test(spawn_path_test_t *test)
{
	pid_t fork_pid;
	siginfo_t sig;

	fork_pid = forkx(FORK_NOSIGCHLD | FORK_WAITPID);
	if (fork_pid == -1) {
		err(EXIT_FAILURE, "INTERNAL TEST ERROR: %s: fork",
		    test->spt_desc);
	}

	if (fork_pid == 0) {
		char *argv[] = { (char *)test->spt_file, NULL };
		siginfo_t child_sig;
		pid_t pid;
		int ret;

		/* Child: set up PATH and attempt posix_spawnp */
		if (test->spt_path != NULL) {
			if (setenv("PATH", test->spt_path, 1) != 0)
				_exit(99);
		} else {
			if (unsetenv("PATH") != 0)
				_exit(99);
		}

		ret = posix_spawnp(&pid, test->spt_file, NULL, NULL,
		    argv, environ);

		if (ret != 0) {
			if (!test->spt_pass && ret == test->spt_err)
				_exit(0);
			/*
			 * Encode the errno in the exit status for
			 * diagnostics. Use values > 100 to distinguish
			 * from normal exits.
			 */
			_exit(100 + ret);
		}

		/* posix_spawn succeeded. Wait for the spawned process */
		if (waitid(P_PID, pid, &child_sig, WEXITED) != 0)
			_exit(98);
		if (child_sig.si_code != CLD_EXITED || child_sig.si_status != 0)
			_exit(97);

		/* Expected failure but got success. */
		if (!test->spt_pass)
			_exit(96);

		_exit(0);
	}

	/* Parent: wait for the child */
	if (waitid(P_PID, fork_pid, &sig, WEXITED) != 0) {
		err(EXIT_FAILURE, "INTERNAL TEST ERROR: %s: waitid",
		    test->spt_desc);
	}

	if (sig.si_code != CLD_EXITED) {
		warnx("TEST FAILED: %s: "
		    "fork child did not exit normally: si_code: %d",
		    test->spt_desc, sig.si_code);
		return (false);
	}

	if (sig.si_status != 0) {
		if (sig.si_status == 96) {
			warnx("TEST FAILED: %s: "
			    "expected failure but posix_spawnp succeeded",
			    test->spt_desc);
		} else if (sig.si_status > 100) {
			warnx("TEST FAILED: %s: "
			    "posix_spawnp failed with %s, expected %s",
			    test->spt_desc,
			    strerrorname_np(sig.si_status - 100),
			    test->spt_pass ? "success" :
			    strerrorname_np(test->spt_err));
		} else {
			warnx("TEST FAILED: %s: "
			    "fork child exited with status %d",
			    test->spt_desc, sig.si_status);
		}
		return (false);
	}

	return (true);
}

/*
 * Test ENOEXEC shell fallback: posix_spawnp a script without a #! line.
 * The implementation should fall back to executing it via /bin/sh.
 */
static bool
enoexec_fallback_test(spawn_path_test_t *test)
{
	const char *desc = test->spt_desc;
	pid_t fork_pid;
	siginfo_t sig;

	fork_pid = forkx(FORK_NOSIGCHLD | FORK_WAITPID);
	if (fork_pid == -1)
		err(EXIT_FAILURE, "INTERNAL TEST ERROR: %s: fork", desc);

	if (fork_pid == 0) {
		char *argv[] = { "posix_spawn_noshebang", NULL };
		siginfo_t child_sig;
		pid_t pid;
		int ret;

		if (setenv("PATH", posix_spawn_noshebang_dir, 1) != 0)
			_exit(99);

		ret = posix_spawnp(&pid, "posix_spawn_noshebang", NULL, NULL,
		    argv, environ);
		if (ret != 0)
			_exit(100 + ret);

		if (waitid(P_PID, pid, &child_sig, WEXITED) != 0)
			_exit(98);
		if (child_sig.si_code != CLD_EXITED ||
		    child_sig.si_status != 0)
			_exit(97);

		_exit(0);
	}

	if (waitid(P_PID, fork_pid, &sig, WEXITED) != 0)
		err(EXIT_FAILURE, "INTERNAL TEST ERROR: %s: waitid", desc);

	if (sig.si_code != CLD_EXITED) {
		warnx("TEST FAILED: %s: "
		    "fork child did not exit normally: si_code: %d",
		    desc, sig.si_code);
		return (false);
	}

	if (sig.si_status != 0) {
		if (sig.si_status > 100) {
			warnx("TEST FAILED: %s: posix_spawnp failed with %s",
			    desc, strerrorname_np(sig.si_status - 100));
		} else {
			warnx("TEST FAILED: %s: "
			    "fork child exited with status %d",
			    desc, sig.si_status);
		}
		return (false);
	}

	return (true);
}

static spawn_path_test_t tests[] = {
	{ .spt_desc = "find true via PATH=/usr/bin",
	    .spt_func = path_resolve_test,
	    .spt_file = "true", .spt_path = "/usr/bin",
	    .spt_pass = true },
	{ .spt_desc = "find true via second PATH component",
	    .spt_func = path_resolve_test,
	    .spt_file = "true", .spt_path = "/usr/lib:/usr/bin",
	    .spt_pass = true },
	{ .spt_desc = "fail with PATH=/devices/nonexistent",
	    .spt_func = path_resolve_test,
	    .spt_file = "true", .spt_path = "/devices/nonexistent",
	    .spt_pass = false, .spt_err = ENOENT },
	{ .spt_desc = "absolute path ignores PATH",
	    .spt_func = path_resolve_test,
	    .spt_file = "/usr/bin/true", .spt_path = "/devices/nonexistent",
	    .spt_pass = true },
	{ .spt_desc = "empty file returns EACCES",
	    .spt_func = path_resolve_test,
	    .spt_file = "", .spt_path = "/usr/bin",
	    .spt_pass = false, .spt_err = EACCES },
	{ .spt_desc = "NULL PATH uses default path",
	    .spt_func = path_resolve_test,
	    .spt_file = "true",
	    .spt_pass = true },
	{ .spt_desc = "ENOEXEC: shell fallback for no-shebang script",
	    .spt_func = enoexec_fallback_test },
	{ .spt_desc = "EACCES from earlier component beats later ENOENT",
	    .spt_func = path_resolve_test,
	    .spt_file = "posix_spawn_noexec", .spt_path = eacces_path,
	    .spt_pass = false, .spt_err = EACCES },
	{ .spt_desc = "over-long PATH component returns ENAMETOOLONG",
	    .spt_func = path_resolve_test,
	    .spt_file = "true", .spt_path = toolong_path,
	    .spt_pass = false, .spt_err = ENAMETOOLONG },
	{ .spt_desc = "over-long PATH component is skipped, search continues",
	    .spt_func = path_resolve_test,
	    .spt_file = "true", .spt_path = toolong_ok_path,
	    .spt_pass = true },
};

static void
path_test_setup(void)
{
	char file[PATH_MAX];
	int fd;

	if (snprintf(noexec_dir, sizeof (noexec_dir),
	    "/tmp/posix_spawn_path.%d", (int)getpid()) >=
	    sizeof (noexec_dir)) {
		errx(EXIT_FAILURE, "noexec directory path too long");
	}
	/*
	 * A scratch directory that holds a non-executable file, used to
	 * provoke EACCES from a PATH search. The directory itself is
	 * searchable, it's the file within it that does not have the
	 * execute bit.
	 */
	if (mkdir(noexec_dir, 0755) != 0)
		err(EXIT_FAILURE, "could not create %s", noexec_dir);
	if (snprintf(file, sizeof (file), "%s/posix_spawn_noexec",
	    noexec_dir) >= sizeof (file)) {
		errx(EXIT_FAILURE, "noexec file path too long");
	}
	if ((fd = open(file, O_CREAT | O_WRONLY, 0644)) == -1)
		err(EXIT_FAILURE, "could not create %s", file);
	VERIFY0(close(fd));

	if (snprintf(eacces_path, sizeof (eacces_path),
	    "%s:/devices/nonexistent", noexec_dir) >= sizeof (eacces_path)) {
		errx(EXIT_FAILURE, "EACCES search path too long");
	}

	(void) memset(toolong_path, 'a', PATH_MAX);
	toolong_path[PATH_MAX] = '\0';

	(void) memcpy(toolong_ok_path, toolong_path, PATH_MAX);
	(void) strlcpy(toolong_ok_path + PATH_MAX, ":/usr/bin",
	    sizeof (toolong_ok_path) - PATH_MAX);
}

static void
path_test_cleanup(void)
{
	char file[PATH_MAX];

	if (snprintf(file, sizeof (file), "%s/posix_spawn_noexec",
	    noexec_dir) < sizeof (file)) {
		(void) unlink(file);
	}
	(void) rmdir(noexec_dir);
}

int
main(void)
{
	int ret = EXIT_SUCCESS;
	char path[PATH_MAX];

	posix_spawn_find_helper(path, sizeof (path), "posix_spawn_noshebang");
	(void) strlcpy(posix_spawn_noshebang_dir, dirname(path),
	    sizeof (posix_spawn_noshebang_dir));

	path_test_setup();

	for (size_t i = 0; i < ARRAY_SIZE(tests); i++) {
		if (tests[i].spt_func(&tests[i]))
			(void) printf("TEST PASSED: %s\n", tests[i].spt_desc);
		else
			ret = EXIT_FAILURE;
	}

	path_test_cleanup();

	if (ret == EXIT_SUCCESS)
		(void) printf("All tests passed successfully!\n");

	return (ret);
}
