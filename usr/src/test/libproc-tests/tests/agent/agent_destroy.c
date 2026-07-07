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
 * This program operates alongside agent_target.c and verifies that libproc
 * can destroy the agent lwp even when an injected system call has to be
 * abandoned part-way through. The private _libproc_test_fail_copyinargs
 * flag makes Psyscall() treat the construction of the injected call's
 * stack frame as failed, which leaves the agent stopped on entry to that
 * call. libproc must abort the pending call and terminate the agent,
 * leaving the target undamaged and controllable. It must do so even
 * though the same failure applies to the _lwp_exit() injection which is
 * used to terminate the agent.
 *
 * Historically this went wrong in two ways. Pdestroy_agent() did not abort
 * a system call latched at an entry stop, so the agent was resumed with the
 * abandoned call still pending and ran off into arbitrary code, crashing or
 * silently corrupting the target. With that fixed, a failure to construct
 * the _lwp_exit() frame abandoned the teardown instead, orphaning the agent
 * and leaving the target stopped forever, since run-on-last-close is
 * skipped for a process which still has an agent lwp. On a libproc with
 * either defect this test crashes the target, or hangs and is timed out by
 * the test runner.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <limits.h>
#include <err.h>
#include <errno.h>
#include <libproc.h>
#include <sys/wait.h>
#include <sys/resource.h>
#include <sys/stat.h>

extern int _libproc_test_fail_copyinargs;

static uint_t at_timeout = 5 * 1000; /* 5s in ms */

/*
 * Verify that the target has no agent lwp, according to both libproc's
 * cached status and the kernel.
 */
static bool
agent_absent(struct ps_prochandle *P)
{
	char path[PATH_MAX];
	struct stat st;

	if (Pstatus(P)->pr_agentid != 0) {
		warnx("TEST FAILED: pstatus reports an agent lwp (id %d)",
		    (int)Pstatus(P)->pr_agentid);
		return (false);
	}

	(void) snprintf(path, sizeof (path), "/proc/%d/lwp/agent",
	    (int)Pstatus(P)->pr_pid);
	if (stat(path, &st) == 0) {
		warnx("TEST FAILED: %s exists: the agent lwp was orphaned",
		    path);
		return (false);
	} else if (errno != ENOENT) {
		warn("TEST FAILED: unexpected error from stat(%s)", path);
		return (false);
	}

	return (true);
}

static bool
agent_checks(struct ps_prochandle *P)
{
	bool ret = true;
	struct rlimit rl;

	/*
	 * Baseline: a normal injection, and with it a full agent
	 * create/destroy cycle, must work.
	 */
	if (pr_getrlimit(P, RLIMIT_NOFILE, &rl) != 0) {
		warn("TEST FAILED: baseline pr_getrlimit() injection failed");
		ret = false;
	} else {
		(void) printf("TEST PASSED: baseline injection succeeded\n");
	}

	if (!agent_absent(P))
		ret = false;

	/*
	 * Force the write which constructs the injected call's stack frame
	 * to fail. The injection itself must fail cleanly, and libproc must
	 * still manage to abort the pending system call and destroy the
	 * agent.
	 */
	_libproc_test_fail_copyinargs = 1;

	if (pr_getrlimit(P, RLIMIT_NOFILE, &rl) == 0) {
		warnx("TEST FAILED: injection unexpectedly succeeded with "
		    "_libproc_test_fail_copyinargs set");
		ret = false;
	} else {
		(void) printf("TEST PASSED: injection failed with "
		    "_libproc_test_fail_copyinargs set\n");
	}

	_libproc_test_fail_copyinargs = 0;

	if (!agent_absent(P)) {
		ret = false;
	} else {
		(void) printf("TEST PASSED: agent destroyed after failed "
		    "injection\n");
	}

	/*
	 * The target must still be intact and controllable.
	 */
	if (pr_getrlimit(P, RLIMIT_NOFILE, &rl) != 0) {
		warn("TEST FAILED: pr_getrlimit() injection failed following "
		    "recovery");
		ret = false;
	} else {
		(void) printf("TEST PASSED: injection succeeded following "
		    "recovery\n");
	}

	if (!agent_absent(P))
		ret = false;

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

	if (Pxlookup_by_name(P, LM_ID_BASE, PR_OBJ_EXEC, "agent_target_hook",
	    &sym, NULL) != 0) {
		err(EXIT_FAILURE, "failed to find agent_target_hook symbol");
	}

	pid = Ppsinfo(P)->pr_pid;

	if (Pfault(P, FLTBPT, 1) != 0)
		errx(EXIT_FAILURE, "failed to set the FLTBPT disposition");

	if (Psetbkpt(P, sym.st_value, &bkpt) != 0) {
		err(EXIT_FAILURE, "failed to set breakpoint on "
		    "agent_target_hook (0x%" PRIx64 ")", sym.st_value);
	}

	if (Psetrun(P, 0, 0) != 0)
		err(EXIT_FAILURE, "failed to resume running our target");

	if (Pwait(P, at_timeout) != 0) {
		err(EXIT_FAILURE, "%s did not hit our expected breakpoint",
		    argv[1]);
	}

	/*
	 * The target is stopped at the breakpoint. Run the injections.
	 */
	if (!agent_checks(P))
		ret = EXIT_FAILURE;

	if (Pdelbkpt(P, sym.st_value, bkpt) != 0)
		err(EXIT_FAILURE, "failed to delete breakpoint");

	if (Psetrun(P, 0, PRCFAULT) != 0)
		err(EXIT_FAILURE, "failed to resume running our target");

	if (waitpid(pid, &wstat, 0) != pid) {
		err(EXIT_FAILURE, "failed to get our %s's (%" _PRIdID "), "
		    "wait info", argv[1], pid);
	}

	if (WIFEXITED(wstat) == 0)
		errx(EXIT_FAILURE, "%s didn't actually exit!", argv[1]);

	if (WEXITSTATUS(wstat) != 0) {
		errx(EXIT_FAILURE, "%s failed with 0x%x", argv[1],
		    WEXITSTATUS(wstat));
	} else {
		(void) printf("TEST PASSED: target ran to completion "
		    "undamaged\n");
	}

	if (ret == EXIT_SUCCESS)
		(void) printf("All tests passed successfully\n");

	return (ret);
}
