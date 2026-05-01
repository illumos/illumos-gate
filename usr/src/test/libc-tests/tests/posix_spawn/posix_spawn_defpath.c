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
 * When PATH is not present in the environment, posix_spawnp(3C) falls back
 * to a default search path. POSIX allows for implementation-defined
 * behaviour here.
 *
 * Our defaults for posix_spawn(3C) are deliberately the same as for execvp(3)
 * and a caller which is traditional root (uid or euid 0) gets a search path
 * containing /usr/sbin, other callers do not. This test verifies that the
 * default is derived from the identity of the /caller/ at the time of the
 * call.
 *
 * We must run as root, and choose to use zdump(8) as the spawn target
 * since it lives only in /usr/sbin and exits successfully when given no
 * arguments.
 */

#include <err.h>
#include <errno.h>
#include <pwd.h>
#include <spawn.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/debug.h>
#include <sys/types.h>
#include <sys/wait.h>

#define	TARGET	"zdump"

extern char **environ;

static bool
spawn_and_reap(const char *desc, const posix_spawnattr_t *attr)
{
	char *argv[] = { TARGET, NULL };
	pid_t pid;
	int ret, status;

	ret = posix_spawnp(&pid, TARGET, NULL, attr, argv, environ);
	if (ret != 0) {
		warnc(ret, "TEST FAILED: %s: posix_spawnp returned %d",
		    desc, ret);
		return (false);
	}

	if (waitpid(pid, &status, 0) != pid) {
		warn("TEST FAILED: %s: waitpid", desc);
		return (false);
	}

	if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
		warnx("TEST FAILED: %s: unexpected wait status %#x",
		    desc, status);
		return (false);
	}

	return (true);
}

int
main(void)
{
	posix_spawnattr_t attr;
	struct passwd *pw;
	int ret = EXIT_SUCCESS;

	if (getuid() != 0 && geteuid() != 0)
		errx(EXIT_FAILURE, "this test must be run as root");

	/* Unset PATH so that the default search path is used */
	VERIFY0(unsetenv("PATH"));

	/*
	 * While still fully privileged (uid 0 and euid 0), the default search
	 * path must include the superuser directories such as /usr/sbin.
	 */
	if (spawn_and_reap("uid 0, euid 0 default path includes /usr/sbin",
	    NULL)) {
		(void) printf("TEST PASSED: uid 0, euid 0 default path "
		    "includes /usr/sbin\n");
	} else {
		ret = EXIT_FAILURE;
	}

	/*
	 * Become a process with euid 0 but a non-root real uid, so that
	 * POSIX_SPAWN_RESETIDS makes the child relinquish privilege.
	 */
	if ((pw = getpwnam("nobody")) == NULL)
		errx(EXIT_FAILURE, "could not look up user 'nobody'");
	VERIFY0(setreuid(pw->pw_uid, 0));

	if (spawn_and_reap("euid 0 default path includes /usr/sbin",
	    NULL)) {
		(void) printf("TEST PASSED: euid 0 default path "
		    "includes /usr/sbin\n");
	} else {
		ret = EXIT_FAILURE;
	}

	VERIFY0(posix_spawnattr_init(&attr));
	VERIFY0(posix_spawnattr_setflags(&attr, POSIX_SPAWN_RESETIDS));

	if (spawn_and_reap("default path unaffected by RESETIDS", &attr)) {
		(void) printf("TEST PASSED: default path unaffected by "
		    "RESETIDS\n");
	} else {
		ret = EXIT_FAILURE;
	}

	VERIFY0(posix_spawnattr_destroy(&attr));

	if (ret == EXIT_SUCCESS)
		(void) printf("All tests passed successfully!\n");

	return (ret);
}
