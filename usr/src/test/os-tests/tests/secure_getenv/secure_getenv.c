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
 * Test whether or not secure_getenv(3C) correctly ratchets off certain
 * privileges. In general, this happens if our uid/euid or gid/egid mismatch or
 * whether or not there was some kind of privilege escalation. We have a checker
 * program that we'll use to actually look at this.
 */

#include <stdlib.h>
#include <err.h>
#include <stdbool.h>
#include <sys/sysmacros.h>
#include <unistd.h>
#include <sys/fork.h>
#include <wait.h>
#include <pwd.h>
#include <limits.h>
#include <libgen.h>
#include <sys/debug.h>
#include <priv.h>

static const char *getenv_checker = "checker";
static char getenv_path[PATH_MAX];
static struct passwd *getenv_nobody;

typedef struct {
	const char *gf_desc;
	bool gf_secure;
	void (*gf_forker)(const char *);
} getenv_fork_t;

/*
 * Set all of our effective IDs to nobody.
 */
static void
getenv_fork_nobody(const char *desc)
{
	if (setgid(getenv_nobody->pw_gid) != 0) {
		errx(EXIT_FAILURE, "TEST FAILED: %s: failed to setgid to "
		    "nobody (%u)", desc, getenv_nobody->pw_gid);
	}

	if (setuid(getenv_nobody->pw_uid) != 0) {
		errx(EXIT_FAILURE, "TEST FAILED: %s: failed to setuid to "
		    "nobody (%u)", desc, getenv_nobody->pw_uid);
	}
}

static void
getenv_fork_seteuid(const char *desc)
{
	if (seteuid(getenv_nobody->pw_uid) != 0) {
		errx(EXIT_FAILURE, "TEST FAILED: %s: failed to seteuid to "
		    "nobody (%u)", desc, getenv_nobody->pw_uid);
	}
}

static void
getenv_fork_setegid(const char *desc)
{
	if (setegid(getenv_nobody->pw_gid) != 0) {
		errx(EXIT_FAILURE, "TEST FAILED: %s: failed to setegid to "
		    "nobody (%u)", desc, getenv_nobody->pw_gid);
	}
}

static void
getenv_fork_seteugid(const char *desc)
{
	getenv_fork_setegid(desc);
	getenv_fork_seteuid(desc);
}

/*
 * An executing process is considered to have a privilege increase if the
 * inheritable set is larger than the permitted set. Because this is launched as
 * a privileged process we generally have a default inheritable set of 'basic',
 * but our permitted is 'all'. So we first increase our inheritable set and then
 * drop our permitted set.
 */
static void
getenv_fork_privs(const char *desc)
{
	priv_set_t *priv = priv_allocset();

	if (priv == NULL) {
		err(EXIT_FAILURE, "TEST FAILED: %s: failed to allocate a "
		    "priv_set_t", desc);
	}

	VERIFY0(priv_addset(priv, PRIV_PROC_CLOCK_HIGHRES));
	if (setppriv(PRIV_ON, PRIV_INHERITABLE, priv) != 0) {
		err(EXIT_FAILURE, "TEST FAILED: %s: failed to add privs to "
		    "the inheritable set", desc);
	}

	priv_basicset(priv);
	if (setppriv(PRIV_SET, PRIV_PERMITTED, priv) != 0) {
		err(EXIT_FAILURE, "TEST FAILED: %s: failed to set permitted "
		    "set to the basic set", desc);
	}

	priv_freeset(priv);
}

static const getenv_fork_t getenv_tests[] = { {
	.gf_desc = "change all to nobody",
	.gf_secure = false,
	.gf_forker = getenv_fork_nobody
}, {
	.gf_desc = "seteuid to nobody",
	.gf_secure = true,
	.gf_forker = getenv_fork_seteuid
}, {
	.gf_desc = "setegid to nobody",
	.gf_secure = true,
	.gf_forker = getenv_fork_setegid
}, {
	.gf_desc = "sete[ug]id to nobody",
	.gf_secure = true,
	.gf_forker = getenv_fork_seteugid
}, {
	.gf_desc = "privilege increase",
	.gf_secure = true,
	.gf_forker = getenv_fork_privs
} };

static bool
getenv_fork(const getenv_fork_t *test)
{
	pid_t child;
	siginfo_t cret;

	child = forkx(FORK_NOSIGCHLD | FORK_WAITPID);
	if (child == 0) {
		char *argv[4] = { (char *)getenv_checker, (char *)test->gf_desc,
		    NULL, NULL };
		if (test->gf_secure) {
			argv[2] = "secure";
		}
		test->gf_forker(test->gf_desc);
		(void) execv(getenv_path, argv);
		warn("TEST FAILED: %s: failed to exec verifier %s",
		    test->gf_desc, getenv_path);
		_exit(EXIT_FAILURE);
	}

	if (waitid(P_PID, child, &cret, WEXITED) < 0) {
		err(EXIT_FAILURE, "TEST FAILED: internal test failure waiting "
		    "for forked child to report");
	}

	if (cret.si_code != CLD_EXITED) {
		warnx("TEST FAILED: %s: child process did not successfully "
		    "exit: found si_code: %d", test->gf_desc, cret.si_code);
		return (false);
	} else if (cret.si_status != 0) {
		warnx("TEST FAILED: %s: child process did not exit with code "
		    "0: found %d", test->gf_desc, cret.si_status);
		return (false);
	}

	return (true);
}

static void
getenv_getpath(void)
{
	ssize_t ret;
	char dir[PATH_MAX];

	ret = readlink("/proc/self/path/a.out", dir, sizeof (dir));
	if (ret < 0) {
		err(EXIT_FAILURE, "INTERNAL TEST FAILURE: failed to read our "
		    "a.out path from /proc");
	} else if (ret == 0) {
		errx(EXIT_FAILURE, "INTERNAL TEST FAILURE: reading "
		    "/proc/self/path/a.out returned 0 bytes");
	} else if (ret == sizeof (dir)) {
		errx(EXIT_FAILURE, "INTERNAL TEST FAILURE: Using "
		    "/proc/self/path/a.out requires truncation");
	}

	dir[ret] = '\0';
	if (snprintf(getenv_path, sizeof (getenv_path), "%s/%s", dirname(dir),
	    getenv_checker) >= sizeof (getenv_path)) {
		errx(EXIT_FAILURE, "INTERNAL TEST FAILURE: constructing path "
		    "for child process would overflow internal buffer");
	}
}

int
main(void)
{
	int ret = EXIT_SUCCESS;

	(void) clearenv();
	if (putenv("SECRET=keep it safe") != 0) {
		errx(EXIT_FAILURE, "INTERNAL TEST FAILURE: failed to put "
		    "environment variable");
	}
	VERIFY3P(getenv("SECRET"), !=, NULL);

	getenv_getpath();
	if ((getenv_nobody = getpwnam("nobody")) == NULL) {
		err(EXIT_FAILURE, "failed to get passwd entry for nobody");
	}

	for (size_t i = 0; i < ARRAY_SIZE(getenv_tests); i++) {
		if (!getenv_fork(&getenv_tests[i]))
			ret = EXIT_FAILURE;
	}

	if (ret == EXIT_SUCCESS) {
		(void) printf("All tests passed successfully\n");
	}

	return (ret);
}
