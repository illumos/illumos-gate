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
 * Tests for the raw spawn(2) system call interface. These concentrate
 * mainly on checking that the kernel fully validates the marshalled
 * spawn_param_t/spawn_args_t structures that libc constructs.
 * We also test that a spawned child is robust against being killed in
 * the window between creation and exec.
 *
 * Functional coverage of posix_spawn(3C) itself (attributes, file actions,
 * PATH handling, etc.) lives in libc-tests/tests/posix_spawn.
 */

#include <errno.h>
#include <signal.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/spawn_impl.h>
#include <sys/types.h>
#include <sys/wait.h>

static uint_t failures = 0;

#define	TFAIL(name, fmt, ...)	do {					\
	(void) fprintf(stderr, "TEST FAILED: %s: " fmt "\n",		\
	    (name), ##__VA_ARGS__);					\
	failures++;							\
} while (0)

#define	TPASS(name)	(void) printf("TEST PASSED: %s\n", (name))

/*
 * The spawn_args_t and spawn_param_t structures end in a variable-length
 * data[] region. These tests build small instances on the stack and reserve a
 * fixed amount of room for that region.
 */
#define	SA_DATA	16
#define	SP_DATA	64

static pid_t
raw_spawn(const char *path, const void *sp, uint32_t spsize, const void *sa,
    uint32_t sasize)
{
	return (syscall(SYS_spawn, path, sp, spsize, sa, sasize));
}

/*
 * Build a minimal valid spawn_args_t in the provided buffer:
 * argv = { "x" }, empty environment.
 */
static uint32_t
valid_args(spawn_args_t *sa)
{
	uint32_t sasize = sizeof (*sa) + 2;

	(void) memset(sa, 0, sasize);
	sa->sa_size = sasize;
	sa->sa_datalen = 2;
	sa->sa_arg_cnt = 1;
	sa->sa_env_off = 2;
	sa->sa_data[0] = 'x';
	sa->sa_data[1] = '\0';

	return (sasize);
}

static const char *
errname(int err)
{
	const char *name = strerrorname_np(err);

	return (name != NULL ? name : "?");
}

static void
expect_err(const char *name, int wanted, const char *path, const void *sp,
    uint32_t spsize, const void *sa, uint32_t sasize)
{
	pid_t pid = raw_spawn(path, sp, spsize, sa, sasize);

	if (pid != -1) {
		TFAIL(name, "spawn unexpectedly succeeded (pid %d)",
		    (int)pid);
		(void) waitpid(pid, NULL, 0);
		return;
	}
	if (errno != wanted) {
		TFAIL(name, "got %s (%d), wanted %s (%d)", errname(errno),
		    errno, errname(wanted), wanted);
		return;
	}
	TPASS(name);
}

/*
 * The positive case: a well-formed minimal request - a valid argument vector,
 * no spawn parameters and no file actions - succeeds, and the child
 * (/usr/bin/true) exits 0.
 */
static void
t_valid(void)
{
	union {
		spawn_args_t sa;
		char pad[sizeof (spawn_args_t) + SA_DATA];
	} au;
	uint32_t sasize = valid_args(&au.sa);
	int status;
	pid_t pid;

	pid = raw_spawn("/usr/bin/true", NULL, 0, &au.sa, sasize);
	if (pid == -1) {
		TFAIL("valid", "spawn failed: %s", strerror(errno));
		return;
	}
	if (waitpid(pid, &status, 0) != pid) {
		TFAIL("valid", "waitpid: %s", strerror(errno));
		return;
	}
	if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
		TFAIL("valid", "status %#x", status);
		return;
	}
	TPASS("valid, well-formed, minimal spawn request");
}

static void
t_args_fuzz(void)
{
	union {
		spawn_args_t sa;
		char pad[sizeof (spawn_args_t) + SA_DATA];
	} au;
	spawn_args_t *sa = &au.sa;
	uint32_t sasize;

	expect_err("null-path", EINVAL, NULL, NULL, 0, &au.sa,
	    valid_args(&au.sa));
	expect_err("null-args", EINVAL, "/usr/bin/true", NULL, 0, NULL, 0);

	sasize = valid_args(sa);
	sa->sa_size = sasize + 8;
	expect_err("args-size-mismatch", EINVAL, "/usr/bin/true", NULL, 0,
	    sa, sasize);

	sasize = valid_args(sa);
	sa->sa_datalen = 1;
	expect_err("args-datalen-mismatch", EINVAL, "/usr/bin/true", NULL, 0,
	    sa, sasize);

	sasize = valid_args(sa);
	sa->sa_arg_cnt = 100;
	expect_err("args-cnt-overrun", EINVAL, "/usr/bin/true", NULL, 0,
	    sa, sasize);

	sasize = valid_args(sa);
	sa->sa_data[1] = 'y';	/* string no longer NUL-terminated */
	expect_err("args-unterminated", EINVAL, "/usr/bin/true", NULL, 0,
	    sa, sasize);

	sasize = valid_args(sa);
	sa->sa_env_off = 100;
	expect_err("args-env-off", EINVAL, "/usr/bin/true", NULL, 0,
	    sa, sasize);

	sasize = valid_args(sa);
	sa->sa_env_cnt = 7;
	expect_err("args-env-cnt", EINVAL, "/usr/bin/true", NULL, 0,
	    sa, sasize);

	sasize = valid_args(sa);
	expect_err("args-e2big", E2BIG, "/usr/bin/true", NULL, 0,
	    sa, 0x400000);

	/* Truncated buffer: shorter than the header itself. */
	sasize = valid_args(sa);
	expect_err("args-short", EINVAL, "/usr/bin/true", NULL, 0,
	    sa, sizeof (*sa) - 4);
}

static void
t_param_fuzz(void)
{
	union {
		spawn_args_t sa;
		char pad[sizeof (spawn_args_t) + SA_DATA];
	} au;
	union {
		spawn_param_t sp;
		char pad[sizeof (spawn_param_t) + SP_DATA];
	} pu;
	spawn_param_t *sp = &pu.sp;
	uint32_t sasize = valid_args(&au.sa);
	uint32_t spsize = sizeof (*sp) + SP_DATA;
	kfile_attr_t *kfa;

	/* Size field disagreeing with the system call argument. */
	(void) memset(&pu, 0, sizeof (pu));
	sp->sp_size = spsize + 4;
	sp->sp_datalen = SP_DATA;
	expect_err("param-size-mismatch", EINVAL, "/usr/bin/true",
	    sp, spsize, &au.sa, sasize);

	/* Attribute region out of bounds. */
	(void) memset(&pu, 0, sizeof (pu));
	sp->sp_size = spsize;
	sp->sp_datalen = SP_DATA;
	sp->sp_attr_off = 60;
	sp->sp_attr_len = sizeof (spawn_attr_t);
	expect_err("param-attr-off", EINVAL, "/usr/bin/true",
	    sp, spsize, &au.sa, sasize);

	/* Attribute length that is not sizeof (spawn_attr_t). */
	(void) memset(&pu, 0, sizeof (pu));
	sp->sp_size = spsize;
	sp->sp_datalen = SP_DATA;
	sp->sp_attr_len = 8;
	expect_err("param-attr-len", EINVAL, "/usr/bin/true",
	    sp, spsize, &au.sa, sasize);

	/* Undefined attribute flags. */
	(void) memset(&pu, 0, sizeof (pu));
	sp->sp_size = spsize;
	sp->sp_datalen = SP_DATA;
	sp->sp_attr_off = 0;
	sp->sp_attr_len = sizeof (spawn_attr_t);
	((spawn_attr_t *)&sp->sp_data[0])->sa_psflags = ~0;
	expect_err("param-attr-flags", EINVAL, "/usr/bin/true",
	    sp, spsize, &au.sa, sasize);

	/* File action record with a zero length. */
	(void) memset(&pu, 0, sizeof (pu));
	sp->sp_size = spsize;
	sp->sp_datalen = SP_DATA;
	sp->sp_fattr_cnt = 2;
	expect_err("param-fattr-len", EINVAL, "/usr/bin/true",
	    sp, spsize, &au.sa, sasize);

	/* File action record with a bad type. */
	(void) memset(&pu, 0, sizeof (pu));
	sp->sp_size = spsize;
	sp->sp_datalen = SP_DATA;
	sp->sp_fattr_cnt = 1;
	kfa = (kfile_attr_t *)&sp->sp_data[0];
	kfa->kfa_len = sizeof (*kfa);
	kfa->kfa_type = 666;
	expect_err("param-fattr-type", EINVAL, "/usr/bin/true",
	    sp, spsize, &au.sa, sasize);

	/* FA_CHDIR with an unterminated path. */
	(void) memset(&pu, 0, sizeof (pu));
	sp->sp_size = spsize;
	sp->sp_datalen = SP_DATA;
	sp->sp_fattr_cnt = 1;
	kfa = (kfile_attr_t *)&sp->sp_data[0];
	kfa->kfa_type = FA_CHDIR;
	kfa->kfa_pathsize = 4;
	kfa->kfa_len = sizeof (*kfa) + 4;
	(void) memcpy(kfa->kfa_path, "/tmp", 4);	/* no NUL */
	expect_err("param-chdir-nul", EINVAL, "/usr/bin/true",
	    sp, spsize, &au.sa, sasize);

	/* Unterminated shell and search path strings. */
	(void) memset(&pu, 0, sizeof (pu));
	sp->sp_size = spsize;
	sp->sp_datalen = SP_DATA;
	sp->sp_shell_off = 0;
	sp->sp_shell_len = 4;
	(void) memcpy(sp->sp_data, "/bin", 4);
	expect_err("param-shell-nul", EINVAL, "/usr/bin/true",
	    sp, spsize, &au.sa, sasize);

	(void) memset(&pu, 0, sizeof (pu));
	sp->sp_size = spsize;
	sp->sp_datalen = SP_DATA;
	sp->sp_path_off = 62;
	sp->sp_path_len = 8;
	expect_err("param-path-off", EINVAL, "/usr/bin/true",
	    sp, spsize, &au.sa, sasize);

	expect_err("param-e2big", E2BIG, "/usr/bin/true",
	    sp, 0x400000, &au.sa, sasize);

	expect_err("param-short", EINVAL, "/usr/bin/true",
	    sp, sizeof (*sp) - 4, &au.sa, sasize);
}

/*
 * Build a spawn_param_t carrying an attribute region with
 * POSIX_SPAWN_SETSCHEDPARAM set and a scheduling region with the given
 * operation.
 */
static kspawn_sched_t *
valid_sched(spawn_param_t *sp, uint32_t spsize, int op)
{
	spawn_attr_t *spa;
	kspawn_sched_t *ks;

	(void) memset(sp, 0, spsize);
	sp->sp_size = spsize;
	sp->sp_datalen = spsize - sizeof (*sp);
	sp->sp_attr_off = 0;
	sp->sp_attr_len = sizeof (spawn_attr_t);
	spa = (spawn_attr_t *)&sp->sp_data[0];
	spa->sa_psflags = POSIX_SPAWN_SETSCHEDPARAM;
	sp->sp_sched_off = sizeof (spawn_attr_t);
	sp->sp_sched_len = sizeof (kspawn_sched_t);
	ks = (kspawn_sched_t *)&sp->sp_data[sp->sp_sched_off];
	ks->ksched_op = op;

	return (ks);
}

static void
t_sched_fuzz(void)
{
	union {
		spawn_args_t sa;
		char pad[sizeof (spawn_args_t) + SA_DATA];
	} au;
	union {
		spawn_param_t sp;
		char pad[sizeof (spawn_param_t) + 128];
	} pu;
	spawn_param_t *sp = &pu.sp;
	uint32_t sasize = valid_args(&au.sa);
	uint32_t spsize = sizeof (*sp) + 128;
	kspawn_sched_t *ks;

	/* Scheduling flag set but no scheduling region. */
	(void) valid_sched(sp, spsize, KSCHED_PARMS);
	sp->sp_sched_off = sp->sp_sched_len = 0;
	expect_err("sched-missing", EINVAL, "/usr/bin/true",
	    sp, spsize, &au.sa, sasize);

	/* Scheduling region present without a scheduling flag. */
	(void) valid_sched(sp, spsize, KSCHED_PARMS);
	((spawn_attr_t *)&sp->sp_data[0])->sa_psflags = 0;
	expect_err("sched-no-flags", EINVAL, "/usr/bin/true",
	    sp, spsize, &au.sa, sasize);

	/* Scheduling region with the wrong length. */
	(void) valid_sched(sp, spsize, KSCHED_PARMS);
	sp->sp_sched_len = 8;
	expect_err("sched-len", EINVAL, "/usr/bin/true",
	    sp, spsize, &au.sa, sasize);

	/* Scheduling region out of bounds. */
	(void) valid_sched(sp, spsize, KSCHED_PARMS);
	sp->sp_sched_off = sp->sp_datalen - 4;
	expect_err("sched-off", EINVAL, "/usr/bin/true",
	    sp, spsize, &au.sa, sasize);

	/* Invalid operation. */
	(void) valid_sched(sp, spsize, 0);
	expect_err("sched-op", EINVAL, "/usr/bin/true",
	    sp, spsize, &au.sa, sasize);

	/* A priority change must be a set operation. */
	ks = valid_sched(sp, spsize, KSCHED_PRIO);
	ks->ksched_prio.pc_op = PC_GETPRIO;
	ks->ksched_prio.pc_cid = 1;
	expect_err("sched-prio-op", EINVAL, "/usr/bin/true",
	    sp, spsize, &au.sa, sasize);

	/*
	 * Class IDs out of range. These are not caught until the child
	 * applies the attributes to itself, exercising the error handshake.
	 */
	ks = valid_sched(sp, spsize, KSCHED_PRIO);
	ks->ksched_prio.pc_op = PC_SETPRIO;
	ks->ksched_prio.pc_cid = 999;
	expect_err("sched-prio-cid", EINVAL, "/usr/bin/true",
	    sp, spsize, &au.sa, sasize);

	ks = valid_sched(sp, spsize, KSCHED_PARMS);
	ks->ksched_parms.pc_cid = 999;
	expect_err("sched-parms-cid", EINVAL, "/usr/bin/true",
	    sp, spsize, &au.sa, sasize);
}

/*
 * A child killed immediately after spawn(2) returns must be waitable and
 * must never leave the parent stuck. We try a few times to give us a fighting
 * chance of catching it.
 */
static void
t_kill_race(void)
{
	union {
		spawn_args_t sa;
		char pad[sizeof (spawn_args_t) + SA_DATA];
	} au;
	uint32_t sasize = valid_args(&au.sa);

	/*
	 * Spawn a child and immediately kill it, over and over, to exercise
	 * the window between creation and exec. valid_args() supplies only
	 * argv[0], so sleep runs with no duration. That does not matter,
	 * because we SIGKILL it at once - all we need is a live PID to race
	 * against.
	 */
	for (int i = 0; i < 100; i++) {
		int status;
		pid_t pid;

		pid = raw_spawn("/usr/bin/sleep", NULL, 0, &au.sa, sasize);
		if (pid == -1) {
			TFAIL("kill-race", "spawn failed: %s",
			    strerror(errno));
			return;
		}
		(void) kill(pid, SIGKILL);
		if (waitpid(pid, &status, 0) != pid) {
			TFAIL("kill-race", "waitpid: %s", strerror(errno));
			return;
		}
		if (!WIFSIGNALED(status) &&
		    !(WIFEXITED(status) && WEXITSTATUS(status) != 0)) {
			TFAIL("kill-race", "iteration %d: status %#x",
			    i, status);
			return;
		}
	}
	TPASS("kill-race");
}

int
main(void)
{
	t_valid();
	t_args_fuzz();
	t_param_fuzz();
	t_sched_fuzz();
	t_kill_race();

	if (failures == 0) {
		(void) printf("All tests passed\n");
		return (EXIT_SUCCESS);
	}

	(void) fprintf(stderr, "%u test(s) failed\n", failures);
	return (EXIT_FAILURE);
}
