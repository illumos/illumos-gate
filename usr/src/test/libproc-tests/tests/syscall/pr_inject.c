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
 * This program is designed to operate alongside pr_target.c. It verifies that
 * we can run a program with libproc and inject various system calls via the
 * agent LWP. It has a contract with pr_target.c to inject operations at the
 * function 'pr_target_hook()'. pr_target.c will then verify that those
 * operations are visible.
 */

#include <stdlib.h>
#include <err.h>
#include <libproc.h>
#include <errno.h>
#include <sys/wait.h>
#include <stdbool.h>
#include <sys/debug.h>
#include <string.h>

#include "pr_target.h"

static uint_t pr_timeout = 5 * 1000; /* 5s in ms */

/*
 * Verify a few things about the state before we inject a bunch of things.
 */
static bool
pr_check_pre(struct ps_prochandle *P)
{
	bool ret = true;
	int fd;
	struct stat st, targ;

	if ((fd = open("/dev/null", O_RDONLY)) < 0) {
		err(EXIT_FAILURE, "TEST FAILED: failed to open /dev/null");
	}

	if (fstat(fd, &st) != 0) {
		err(EXIT_FAILURE, "TEST FAILED: failed to fstat /dev/null");
	}
	VERIFY0(close(fd));

	if (pr_fstat(P, PRT_NULL_FD, &targ) != 0) {
		warn("TEST FAILED: pr_fstat() on target failed");
		ret = false;
	} else {
		(void) printf("TEST PASSED: successfully injected fstat()\n");
	}

	if (st.st_ino != targ.st_ino || st.st_dev != targ.st_dev ||
	    st.st_rdev != targ.st_rdev) {
		warnx("TEST FAILED: pr_fstat() data does not match local "
		    "/dev/null fstat() data");
		ret = false;
	} else {
		(void) printf("TEST PASSED: pr_fstat() data on /dev/null "
		    "matched local data\n");
	}

	if (pr_fstat(P, PRT_ZERO_FD, &targ) == 0) {
		warnx("TEST FAILED: Injected pr_fstat() on fd %u worked "
		    "but expected it not to exist!", PRT_ZERO_FD);
		ret = false;
	} else if (errno != EBADF) {
		int e = errno;
		warnx("TEST FAILED: expected pr_fstat on fd %u to return %s "
		    "but found %s", PRT_ZERO_FD, strerrorname_np(EBADF),
		    strerrorname_np(e));
		ret = false;
	} else {
		(void) printf("TEST PASSED: pr_fstat() on bad fd returned "
		    "EBADF\n");
	}

	return (ret);
}

static bool
pr_inject(struct ps_prochandle *P)
{
	bool ret = true;
	uintptr_t farg0, farg1;
	int fd;

	fd = pr_open(P, "/dev/zero", PRT_ZERO_OFLAG, 0);
	if (fd < 0) {
		warnx("TEST FAILED: failed to open /dev/zero in the target");
		ret = false;
	} else if (fd != PRT_ZERO_FD) {
		warnx("TEST FAILED: pr_open() didn't return FD %u as expected "
		    "but fd %u", PRT_ZERO_FD, fd);
		ret = false;
	} else {
		(void) printf("TEST PASSED: open() successfully injected\n");
	}

	farg0 = PRT_NULL_FD;
	fd = pr_fcntl(P, PRT_NULL_FD, F_DUPFD, (void *)farg0, NULL);
	if (fd < 0) {
		warn("TEST FAILED: failed to inject F_DUPFD fcntl");
		ret = false;
	} else if (fd != PRT_DUP_FD) {
		warnx("TEST FAILED: F_DUPFD didn't return FD %u as expected "
		    "but fd %u", PRT_ZERO_FD, fd);
		ret = false;
	} else {
		(void) printf("TEST PASSED: F_DUPFD successfully injected\n");
	}

	farg0 = PRT_CLOFORK_FD;
	fd = pr_fcntl(P, PRT_NULL_FD, F_DUP2FD_CLOFORK, (void *)farg0, NULL);
	if (fd < 0) {
		warn("TEST FAILED: failed to inject F_DUP2FD_CLOFORK fcntl");
		ret = false;
	} else if (fd != PRT_CLOFORK_FD) {
		warnx("TEST FAILED: F_DUP2FD_CLOFORK didn't return FD %u as "
		    "expected but fd %u", PRT_ZERO_FD, fd);
		ret = false;
	} else {
		(void) printf("TEST PASSED: F_DUP2FD_CLOFORK successfully "
		    "injected\n");
	}

	farg0 = PRT_DUP3_FD;
	farg1 = PRT_DUP3_GETFD;
	fd = pr_fcntl(P, PRT_ZERO_FD, F_DUP3FD, (void *)farg0, (void *)farg1);
	if (fd < 0) {
		warn("TEST FAILED: failed to inject F_DUP3FD fcntl");
		ret = false;
	} else if (fd != PRT_DUP3_FD) {
		warnx("TEST FAILED: F_DUP3FD didn't return FD %u as expected "
		    "but fd %u", PRT_ZERO_FD, fd);
		ret = false;
	} else {
		(void) printf("TEST PASSED: F_DUP3FD successfully injected\n");
	}

	if (pr_close(P, PRT_CLOSE_FD) != 0) {
		warn("TEST FAILED: failed to inject close()");
		ret = false;
	} else {
		(void) printf("TEST PASSED: close() successfully injected\n");
	}

	return (ret);
}

int
main(int argc, char *argv[])
{
	int ret = EXIT_SUCCESS, perr, wstat;
	struct ps_prochandle *P;
	GElf_Sym sym;
	ulong_t bkpt;
	pid_t pid;

	if (argc != 2) {
		errx(EXIT_FAILURE, "missing required program to inject "
		    "against");
	}

	P = Pcreate(argv[1], &argv[1], &perr, NULL, 0);
	if (P == NULL) {
		errx(EXIT_FAILURE, "failed to create %s: %s (0x%x)", argv[1],
		    Pcreate_error(perr), perr);
	}

	(void) Punsetflags(P, PR_RLC);
	if (Psetflags(P, PR_KLC | PR_BPTADJ) != 0) {
		int e = errno;
		Prelease(P, PRELEASE_KILL);
		errc(EXIT_FAILURE, e, "failed to set PR_KLC | PR_BPTADJ flags");
	}

	if (Pxlookup_by_name(P, LM_ID_BASE, PR_OBJ_EXEC, "pr_target_hook", &sym,
	    NULL) != 0) {
		err(EXIT_FAILURE, "failed to find pr_target_hook symbol");
	}

	pid = Ppsinfo(P)->pr_pid;

	if (Pfault(P, FLTBPT, 1) != 0) {
		errx(EXIT_FAILURE, "failed to set the FLTBPT disposition");
	}

	if (Psetbkpt(P, sym.st_value, &bkpt) != 0) {
		err(EXIT_FAILURE, "failed to set breakpoint on pr_target_hook "
		    "(0x%" PRIx64 ")", sym.st_value);
	}

	if (Psetrun(P, 0, 0) != 0) {
		err(EXIT_FAILURE, "failed to resume running our target");
	}

	if (Pwait(P, pr_timeout) != 0) {
		err(EXIT_FAILURE, "%s did not hit our expected breakpoint",
		    argv[1]);
	}

	/*
	 * This is where we actually perform all of our injections and
	 * validations. By hitting the breakpoint the expected fd should exist.
	 */
	if (!pr_check_pre(P)) {
		ret = EXIT_FAILURE;
	}

	if (!pr_inject(P)) {
		ret = EXIT_FAILURE;
	}

	if (Pdelbkpt(P, sym.st_value, bkpt) != 0) {
		err(EXIT_FAILURE, "failed to delete breakpoint");
	}

	if (Psetrun(P, 0, PRCFAULT) != 0) {
		err(EXIT_FAILURE, "failed to resume running our target");
	}

	if (waitpid(pid, &wstat, 0) != pid) {
		err(EXIT_FAILURE, "failed to get our %s's (%" _PRIdID "), "
		    "wait info", argv[1], pid);
	}

	if (WIFEXITED(wstat) == 0) {
		errx(EXIT_FAILURE, "%s didn't actually exit!",
		    argv[1]);
	}

	if (WEXITSTATUS(wstat) != 0) {
		errx(EXIT_FAILURE, "%s failed with 0x%x", argv[1],
		    WEXITSTATUS(wstat));
	} else {
		(void) printf("TEST PASSED: target process self-verification "
		    "passed\n");
	}

	if (ret == EXIT_SUCCESS) {
		(void) printf("All tests passed successfully\n");
	}

	return (ret);
}
