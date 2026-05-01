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
 * Privileged posix_spawn attribute tests. The scheduler tests require
 * proc_priocntl and the RESETIDS test requires proc_setid.
 */

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <limits.h>
#include <libproc.h>
#include <priv.h>
#include <project.h>
#include <pwd.h>
#include <rctl.h>
#include <sched.h>
#include <signal.h>
#include <spawn.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <wait.h>
#include <sys/debug.h>
#include <sys/fork.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/task.h>

#include "posix_spawn_common.h"

extern char **environ;

typedef struct spawn_priv_test {
	const char	*spt_name;
	bool		(*spt_func)(struct spawn_priv_test *);
	const char	*spt_priv;
} spawn_priv_test_t;

static char posix_spawn_child_path[PATH_MAX];

/*
 * Spawn the child helper with the given attributes and verify that it
 * reports the expected scheduling policy and priority.
 */
static bool
spawn_sched_check(const char *desc, posix_spawnattr_t *attr, int want_policy,
    int want_prio)
{
	posix_spawn_file_actions_t acts;
	spawn_sched_result_t res;
	ssize_t n;
	bool bret = true;
	char *argv[] = { posix_spawn_child_path, "sched", NULL };
	int pipes[2];

	posix_spawn_pipe_setup(&acts, pipes);

	if (!posix_spawn_run_child(desc, posix_spawn_child_path,
	    &acts, attr, argv)) {
		bret = false;
		goto out;
	}

	n = read(pipes[0], &res, sizeof (res));
	if (n != sizeof (res)) {
		warnx("TEST FAILED: %s: short read from pipe (%zd)", desc, n);
		bret = false;
		goto out;
	}

	if (res.ssr_policy != want_policy) {
		warnx("TEST FAILED: %s: child policy is %d, expected %d",
		    desc, res.ssr_policy, want_policy);
		bret = false;
	}

	if (res.ssr_priority != want_prio) {
		warnx("TEST FAILED: %s: child priority is %d, expected %d",
		    desc, res.ssr_priority, want_prio);
		bret = false;
	}

out:
	VERIFY0(posix_spawn_file_actions_destroy(&acts));
	VERIFY0(close(pipes[1]));
	VERIFY0(close(pipes[0]));

	return (bret);
}

/*
 * SETSCHEDULER: set the child's scheduling policy to a real-time class with a
 * specific priority. Verify the child sees the correct policy and priority.
 */
static bool
setscheduler_test(spawn_priv_test_t *test)
{
	posix_spawnattr_t attr;
	struct sched_param param;
	bool bret;
	int orig_policy, new_policy, prio_min;
	const char *desc = test->spt_name;

	/*
	 * Pick a real-time class that is not the policy for the current
	 * process.
	 */
	orig_policy = sched_getscheduler(0);
	new_policy = (orig_policy != SCHED_FIFO) ? SCHED_FIFO : SCHED_RR;
	prio_min = sched_get_priority_min(new_policy);
	if (prio_min == -1) {
		warn("TEST FAILED: %s: sched_get_priority_min(%d)",
		    desc, new_policy);
		return (false);
	}

	VERIFY0(posix_spawnattr_init(&attr));
	VERIFY0(posix_spawnattr_setflags(&attr, POSIX_SPAWN_SETSCHEDULER));
	VERIFY0(posix_spawnattr_setschedpolicy(&attr, new_policy));
	param.sched_priority = prio_min;
	VERIFY0(posix_spawnattr_setschedparam(&attr, &param));

	bret = spawn_sched_check(desc, &attr, new_policy, prio_min);

	VERIFY0(posix_spawnattr_destroy(&attr));

	return (bret);
}

/*
 * SETSCHEDULER: set the child's scheduling policy to the fixed-priority
 * class. libc constructs explicit scheduling class parameters only for the
 * TS and RT classes, for everything else it uses the class-independent
 * priority interface, so unlike the test above this exercises that path.
 */
static bool
setscheduler_fx_test(spawn_priv_test_t *test)
{
	posix_spawnattr_t attr;
	struct sched_param param;
	bool bret;
	int prio_max;
	const char *desc = test->spt_name;

	prio_max = sched_get_priority_max(SCHED_FX);
	if (prio_max == -1) {
		warn("TEST FAILED: %s: sched_get_priority_max(SCHED_FX)",
		    desc);
		return (false);
	}
	if (prio_max < 2) {
		warnx("TEST FAILED: %s: FX priority range too small (%d)",
		    desc, prio_max);
		return (false);
	}

	VERIFY0(posix_spawnattr_init(&attr));
	VERIFY0(posix_spawnattr_setflags(&attr, POSIX_SPAWN_SETSCHEDULER));
	VERIFY0(posix_spawnattr_setschedpolicy(&attr, SCHED_FX));
	/* A priority distinguishable from the FX default of 0 */
	param.sched_priority = prio_max / 2;
	VERIFY0(posix_spawnattr_setschedparam(&attr, &param));

	bret = spawn_sched_check(desc, &attr, SCHED_FX, prio_max / 2);

	VERIFY0(posix_spawnattr_destroy(&attr));

	return (bret);
}

/*
 * SETSCHEDPARAM: set only the priority (not the policy). The child should
 * inherit the parent's scheduling policy but with the specified priority.
 * We first switch to a real-time scheduler so the child's policy can be
 * distinguished from the system default.
 */
static bool
setschedparam_test(spawn_priv_test_t *test)
{
	const char *desc = test->spt_name;
	posix_spawnattr_t attr;
	struct sched_param param, orig_param;
	bool bret;
	int orig_policy, new_policy, parent_policy, prio_min;

	/*
	 * Save the original scheduling policy so we can restore it later.
	 * Don't assume the default is SCHED_OTHER; it may be FSS in a zone.
	 */
	orig_policy = sched_getscheduler(0);
	if (orig_policy == -1) {
		warn("TEST FAILED: %s: sched_getscheduler", desc);
		return (false);
	}
	if (sched_getparam(0, &orig_param) != 0) {
		warn("TEST FAILED: %s: sched_getparam", desc);
		return (false);
	}

	/*
	 * Set ourselves to a real-time class so there is a meaningful priority
	 * range to work with. We pick one that is not the policy for the
	 * current process in case that is the system default - the child's
	 * inherited policy is then distinguishable from any system default.
	 */
	new_policy = (orig_policy != SCHED_FIFO) ? SCHED_FIFO : SCHED_RR;

	prio_min = sched_get_priority_min(new_policy);
	if (prio_min == -1) {
		warn("TEST FAILED: %s: sched_get_priority_min(%d)",
		    desc, new_policy);
		return (false);
	}

	param.sched_priority = prio_min;
	if (sched_setscheduler(0, new_policy, &param) == -1) {
		warn("TEST FAILED: %s: sched_setscheduler(%d) failed",
		    desc, new_policy);
		return (false);
	}

	parent_policy = sched_getscheduler(0);

	VERIFY0(posix_spawnattr_init(&attr));
	VERIFY0(posix_spawnattr_setflags(&attr, POSIX_SPAWN_SETSCHEDPARAM));
	param.sched_priority = prio_min + 1;
	VERIFY0(posix_spawnattr_setschedparam(&attr, &param));

	bret = spawn_sched_check(desc, &attr, parent_policy, prio_min + 1);

	/*
	 * Restore the original scheduling policy.
	 */
	(void) sched_setscheduler(0, orig_policy, &orig_param);

	VERIFY0(posix_spawnattr_destroy(&attr));

	return (bret);
}

/*
 * SETSCHEDPARAM with the parent in the fixed-priority class. The child
 * inherits FX and the priority change is applied through the
 * class-independent priority interface, as for the FX SETSCHEDULER test
 * above.
 */
static bool
setschedparam_fx_test(spawn_priv_test_t *test)
{
	const char *desc = test->spt_name;
	posix_spawnattr_t attr;
	struct sched_param param, orig_param;
	bool bret;
	int orig_policy, prio_max;

	/*
	 * Save the original scheduling policy so we can restore it later.
	 */
	orig_policy = sched_getscheduler(0);
	if (orig_policy == -1) {
		warn("TEST FAILED: %s: sched_getscheduler", desc);
		return (false);
	}
	if (sched_getparam(0, &orig_param) != 0) {
		warn("TEST FAILED: %s: sched_getparam", desc);
		return (false);
	}

	prio_max = sched_get_priority_max(SCHED_FX);
	if (prio_max == -1) {
		warn("TEST FAILED: %s: sched_get_priority_max(SCHED_FX)",
		    desc);
		return (false);
	}
	if (prio_max < 2) {
		warnx("TEST FAILED: %s: FX priority range too small (%d)",
		    desc, prio_max);
		return (false);
	}

	param.sched_priority = prio_max / 2;
	if (sched_setscheduler(0, SCHED_FX, &param) == -1) {
		warn("TEST FAILED: %s: sched_setscheduler(SCHED_FX) failed",
		    desc);
		return (false);
	}

	VERIFY0(posix_spawnattr_init(&attr));
	VERIFY0(posix_spawnattr_setflags(&attr, POSIX_SPAWN_SETSCHEDPARAM));
	param.sched_priority = prio_max / 2 + 1;
	VERIFY0(posix_spawnattr_setschedparam(&attr, &param));

	bret = spawn_sched_check(desc, &attr, SCHED_FX, prio_max / 2 + 1);

	/*
	 * Restore the original scheduling policy.
	 */
	(void) sched_setscheduler(0, orig_policy, &orig_param);

	VERIFY0(posix_spawnattr_destroy(&attr));

	return (bret);
}

/*
 * Spawn a child and verify that it lands in the same task, project and
 * process contract as its parent. The work is done in a forked child since
 * entering a new task cannot be undone.
 *
 * Exit codes from the forked child, for diagnostics:
 *   99 settaskid failed, 98 posix_spawn failed, 97 could not read psinfo,
 *   96 task id mismatch, 95 project id mismatch, 94 contract id mismatch.
 */
static bool
spawn_task_inherit_test(spawn_priv_test_t *test)
{
	const char *desc = test->spt_name;
	siginfo_t sig;
	pid_t fork_pid;

	fork_pid = forkx(FORK_NOSIGCHLD | FORK_WAITPID);
	if (fork_pid == -1) {
		err(EXIT_FAILURE, "INTERNAL TEST ERROR: %s: fork", desc);
	}

	if (fork_pid == 0) {
		char *argv[] = { "sleep", "30", NULL };
		psinfo_t mine, theirs;
		taskid_t task;
		pid_t pid;
		int status;

		if ((task = settaskid(getprojid(), TASK_NORMAL)) == -1)
			_exit(99);

		if (posix_spawn(&pid, "/usr/bin/sleep", NULL, NULL, argv,
		    environ) != 0) {
			_exit(98);
		}

		if (proc_get_psinfo(getpid(), &mine) != 0 ||
		    proc_get_psinfo(pid, &theirs) != 0) {
			status = 97;
		} else if (theirs.pr_taskid != task ||
		    theirs.pr_taskid != mine.pr_taskid) {
			status = 96;
		} else if (theirs.pr_projid != mine.pr_projid) {
			status = 95;
		} else if (theirs.pr_contract != mine.pr_contract) {
			status = 94;
		} else {
			status = 0;
		}

		(void) kill(pid, SIGKILL);
		(void) waitpid(pid, NULL, 0);
		_exit(status);
	}

	if (waitid(P_PID, fork_pid, &sig, WEXITED) != 0)
		err(EXIT_FAILURE, "INTERNAL TEST ERROR: %s: waitid", desc);

	if (sig.si_code != CLD_EXITED || sig.si_status != 0) {
		warnx("TEST FAILED: %s: fork child reported %d",
		    desc, sig.si_status);
		return (false);
	}

	return (true);
}

/*
 * Spawn under a task.max-lwps resource control that cannot accommodate the
 * child's LWP. The spawn must fail cleanly with EAGAIN.
 *
 * Exit codes: 99 settaskid failed, 98 setrctl failed, 97 spawn unexpectedly
 * succeeded, 100+e spawn failed with unexpected errno e.
 */
static bool
spawn_rctl_fail_test(spawn_priv_test_t *test)
{
	const char *desc = test->spt_name;
	siginfo_t sig;
	pid_t fork_pid;

	fork_pid = forkx(FORK_NOSIGCHLD | FORK_WAITPID);
	if (fork_pid == -1) {
		err(EXIT_FAILURE, "INTERNAL TEST ERROR: %s: fork", desc);
	}

	if (fork_pid == 0) {
		char *argv[] = { "true", NULL };
		rctlblk_t *blk;
		pid_t pid;
		int ret;

		if (settaskid(getprojid(), TASK_NORMAL) == -1)
			_exit(99);

		/*
		 * This process has a single LWP, so a privileged deny limit
		 * of one means the spawned child's LWP must be refused.
		 */
		if ((blk = calloc(1, rctlblk_size())) == NULL)
			_exit(99);
		rctlblk_set_value(blk, 1);
		rctlblk_set_privilege(blk, RCPRIV_PRIVILEGED);
		rctlblk_set_local_action(blk, RCTL_LOCAL_DENY, 0);
		if (setrctl("task.max-lwps", NULL, blk, RCTL_INSERT) != 0)
			_exit(98);

		ret = posix_spawn(&pid, "/usr/bin/true", NULL, NULL, argv,
		    environ);
		if (ret == 0) {
			(void) waitpid(pid, NULL, 0);
			_exit(97);
		}
		if (ret != EAGAIN)
			_exit(100 + ret);
		_exit(0);
	}

	if (waitid(P_PID, fork_pid, &sig, WEXITED) != 0)
		err(EXIT_FAILURE, "INTERNAL TEST ERROR: %s: waitid", desc);

	if (sig.si_code != CLD_EXITED || sig.si_status != 0) {
		if (sig.si_status > 100) {
			warnx("TEST FAILED: %s: spawn failed with %s, "
			    "expected EAGAIN", desc,
			    strerrorname_np(sig.si_status - 100));
		} else {
			warnx("TEST FAILED: %s: fork child reported %d",
			    desc, sig.si_status);
		}
		return (false);
	}

	return (true);
}

/*
 * Look up the 'nobody' user and verify that our current uid is not already
 * nobody, since RESETIDS tests depend on the distinction.
 */
static uid_t
get_nobody_uid(const char *desc)
{
	struct passwd *pwd;

	errno = 0;
	if ((pwd = getpwnam("nobody")) == NULL) {
		err(EXIT_FAILURE,
		    "INTERNAL TEST FAILURE: could not find 'nobody' user");
	}

	if (getuid() == pwd->pw_uid) {
		errx(EXIT_FAILURE,
		    "INTERNAL TEST FAILURE: %s: already running as nobody",
		    desc);
	}

	return (pwd->pw_uid);
}

/*
 * RESETIDS: set euid to nobody, then spawn with RESETIDS. The child should see
 * euid == uid. Requires proc_setid.
 */
static bool
resetids_priv_test(spawn_priv_test_t *test)
{
	const char *desc = test->spt_name;
	int pipes[2];
	posix_spawn_file_actions_t acts;
	posix_spawnattr_t attr;
	spawn_id_result_t res;
	ssize_t n;
	bool bret = true;
	uid_t orig_euid = geteuid();
	uid_t nobody_uid;
	char *argv[] = { posix_spawn_child_path, "ids", NULL };

	nobody_uid = get_nobody_uid(desc);

	/*
	 * Set effective uid to that of 'nobody'. RESETIDS should restore euid
	 * to match uid.
	 */
	if (seteuid(nobody_uid) != 0) {
		warn("TEST FAILED: %s: seteuid(nobody) failed", desc);
		return (false);
	}

	posix_spawn_pipe_setup(&acts, pipes);

	VERIFY0(posix_spawnattr_init(&attr));
	VERIFY0(posix_spawnattr_setflags(&attr, POSIX_SPAWN_RESETIDS));

	if (!posix_spawn_run_child(desc, posix_spawn_child_path,
	    &acts, &attr, argv)) {
		bret = false;
		goto out;
	}

	n = read(pipes[0], &res, sizeof (res));
	if (n != sizeof (res)) {
		warnx("TEST FAILED: %s: short read from pipe (%zd)", desc, n);
		bret = false;
		goto out;
	}

	if (res.sir_uid != res.sir_euid) {
		warnx("TEST FAILED: %s: uid %d != euid %d after RESETIDS",
		    desc, res.sir_uid, res.sir_euid);
		bret = false;
	}

	if (res.sir_uid != getuid()) {
		warnx("TEST FAILED: %s: "
		    "child uid is %d, expected parent's uid %d",
		    desc, res.sir_uid, getuid());
		bret = false;
	}

out:
	(void) seteuid(orig_euid);

	VERIFY0(posix_spawnattr_destroy(&attr));
	VERIFY0(posix_spawn_file_actions_destroy(&acts));
	VERIFY0(close(pipes[1]));
	VERIFY0(close(pipes[0]));

	return (bret);
}

/*
 * RESETIDS with a setuid binary. Create a temporary copy of the child helper
 * owned by 'nobody' with the setuid bit set. The setuid bit is applied by
 * exec(2) after RESETIDS processing, so the child's euid should be nobody
 * in both cases. RESETIDS should not prevent legitimate setuid from working.
 * We verify that uid remains the parent's real uid regardless.
 */
static bool
resetids_suid_test(spawn_priv_test_t *test)
{
	const char *desc = test->spt_name;
	int pipes[2];
	posix_spawn_file_actions_t acts;
	posix_spawnattr_t attr;
	spawn_id_result_t res;
	ssize_t n;
	bool bret = true;
	uid_t nobody_uid;
	uid_t parent_uid = getuid();
	char *argv[] = { posix_spawn_child_path, "ids", NULL };
	char suid_path[PATH_MAX];
	char cmdbuf[PATH_MAX + 64];

	nobody_uid = get_nobody_uid(desc);

	/*
	 * Create a setuid copy of the child helper owned by nobody.
	 */
	if (snprintf(suid_path, sizeof (suid_path),
	    "/tmp/posix_spawn_suid_child.%d", (int)getpid()) >=
	    sizeof (suid_path)) {
		warnx("TEST FAILED: %s: suid path too long", desc);
		return (false);
	}
	if (snprintf(cmdbuf, sizeof (cmdbuf),
	    "cp %s %s", posix_spawn_child_path, suid_path) >= sizeof (cmdbuf)) {
		warnx("TEST FAILED: %s: copy command too long", desc);
		return (false);
	}
	if (system(cmdbuf) != 0) {
		warnx("TEST FAILED: %s: failed to copy child helper", desc);
		return (false);
	}

	if (chown(suid_path, nobody_uid, (gid_t)-1) != 0) {
		warn("TEST FAILED: %s: chown failed", desc);
		(void) unlink(suid_path);
		return (false);
	}

	if (chmod(suid_path, S_ISUID | 0555) != 0) {
		warn("TEST FAILED: %s: chmod failed", desc);
		(void) unlink(suid_path);
		return (false);
	}

	/*
	 * First verify the control case: without RESETIDS, the setuid bit
	 * causes euid to become nobody.
	 */
	posix_spawn_pipe_setup(&acts, pipes);

	argv[0] = suid_path;

	if (!posix_spawn_run_child(desc, suid_path, &acts, NULL, argv)) {
		bret = false;
		VERIFY0(posix_spawn_file_actions_destroy(&acts));
		VERIFY0(close(pipes[1]));
		VERIFY0(close(pipes[0]));
		goto cleanup;
	}

	n = read(pipes[0], &res, sizeof (res));
	if (n != sizeof (res)) {
		warnx("TEST FAILED: %s: control: short read from pipe (%zd)",
		    desc, n);
		bret = false;
	} else if (res.sir_euid != nobody_uid) {
		warnx("TEST FAILED: %s: control: euid is %d, "
		    "expected nobody (%d)",
		    desc, res.sir_euid, nobody_uid);
		bret = false;
	} else if (res.sir_uid != parent_uid) {
		warnx("TEST FAILED: %s: control: uid is %d, "
		    "expected parent uid (%d)",
		    desc, res.sir_uid, parent_uid);
		bret = false;
	}

	VERIFY0(posix_spawn_file_actions_destroy(&acts));
	VERIFY0(close(pipes[1]));
	VERIFY0(close(pipes[0]));

	/*
	 * With RESETIDS: the setuid bit still takes effect (euid = nobody)
	 * because exec applies suid after RESETIDS. The real uid should
	 * remain the parent's real uid.
	 */
	posix_spawn_pipe_setup(&acts, pipes);

	VERIFY0(posix_spawnattr_init(&attr));
	VERIFY0(posix_spawnattr_setflags(&attr, POSIX_SPAWN_RESETIDS));

	if (!posix_spawn_run_child(desc, suid_path, &acts, &attr, argv)) {
		bret = false;
		goto out;
	}

	n = read(pipes[0], &res, sizeof (res));
	if (n != sizeof (res)) {
		warnx("TEST FAILED: %s: short read from pipe (%zd)", desc, n);
		bret = false;
		goto out;
	}

	if (res.sir_euid != nobody_uid) {
		warnx("TEST FAILED: %s: "
		    "euid is %d, expected nobody (%d) (suid > RESETIDS)",
		    desc, res.sir_euid, nobody_uid);
		bret = false;
	}

	if (res.sir_uid != parent_uid) {
		warnx("TEST FAILED: %s: "
		    "uid is %d, expected parent's uid %d",
		    desc, res.sir_uid, parent_uid);
		bret = false;
	}

out:
	VERIFY0(posix_spawnattr_destroy(&attr));
	VERIFY0(posix_spawn_file_actions_destroy(&acts));
	VERIFY0(close(pipes[1]));
	VERIFY0(close(pipes[0]));

cleanup:
	(void) unlink(suid_path);

	return (bret);
}

static spawn_priv_test_t tests[] = {
	{ .spt_name = "SETSCHEDULER: RT SCHED with min priority",
	    .spt_func = setscheduler_test, .spt_priv = PRIV_PROC_PRIOCNTL },
	{ .spt_name = "SETSCHEDULER: FX SCHED with mid-range priority",
	    .spt_func = setscheduler_fx_test, .spt_priv = PRIV_PROC_PRIOCNTL },
	{ .spt_name = "SETSCHEDPARAM: priority change under RT SCHED",
	    .spt_func = setschedparam_test, .spt_priv = PRIV_PROC_PRIOCNTL },
	{ .spt_name = "SETSCHEDPARAM: priority change under FX SCHED",
	    .spt_func = setschedparam_fx_test, .spt_priv = PRIV_PROC_PRIOCNTL },
	{ .spt_name = "RESETIDS: euid reset after seteuid(nobody)",
	    .spt_func = resetids_priv_test, .spt_priv = PRIV_PROC_SETID },
	{ .spt_name = "RESETIDS: setuid binary retains suid euid",
	    .spt_func = resetids_suid_test, .spt_priv = PRIV_PROC_SETID },
	{ .spt_name = "child inherits task, project and contract",
	    .spt_func = spawn_task_inherit_test,
	    .spt_priv = PRIV_PROC_TASKID },
	{ .spt_name = "spawn against task.max-lwps fails with EAGAIN",
	    .spt_func = spawn_rctl_fail_test,
	    .spt_priv = PRIV_SYS_RESOURCE },
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
			if (!priv_ineffect(tests[i].spt_priv)) {
				(void) printf("TEST FAILED: %s: "
				    "requires %s privilege\n",
				    tests[i].spt_name, tests[i].spt_priv);
				ret = EXIT_FAILURE;
			} else if (tests[i].spt_func(&tests[i])) {
				(void) printf("TEST PASSED: %s\n",
				    tests[i].spt_name);
			} else {
				ret = EXIT_FAILURE;
			}
		}
	}

	if (ret == EXIT_SUCCESS)
		(void) printf("All tests passed successfully!\n");

	return (ret);
}
