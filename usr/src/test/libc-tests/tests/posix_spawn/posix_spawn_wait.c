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
 * A thread blocked in posix_spawn(3C) waiting for its child to complete
 * the spawn must not prevent the rest of the process from making progress.
 *
 * This test arranges for the spawn child to be delayed indefinitely by
 * giving it a file action that opens a FIFO for reading while there is no
 * writer. While it is blocked, another thread in the parent forks. fork()
 * begins by holding every other LWP in the process at a safe point, so a
 * successful fork proves that the thread waiting in spawn(2) can be held
 * despite being blocked mid-call. The FIFO is then opened for writing to
 * release the child, and the spawn must complete normally.
 *
 * While the child is parked, before it has exec'd, /proc control operations
 * on it must be refused with EBUSY. The test checks that too.
 */

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <libproc.h>
#include <pthread.h>
#include <signal.h>
#include <spawn.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/debug.h>
#include <sys/param.h>
#include <sys/procfs.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>

extern char **environ;

static char fifopath[MAXPATHLEN];
static pid_t spawn_pid = -1;
static int spawn_ret = -1;
static pid_t child_pid = -1;

static void *
spawn_thread(void *arg __unused)
{
	posix_spawn_file_actions_t fa;
	char *argv[] = { "true", NULL };

	VERIFY0(posix_spawn_file_actions_init(&fa));
	VERIFY0(posix_spawn_file_actions_addopen(&fa, 3, fifopath,
	    O_RDONLY, 0));

	spawn_ret = posix_spawn(&spawn_pid, "/usr/bin/true", &fa, NULL,
	    argv, environ);

	VERIFY0(posix_spawn_file_actions_destroy(&fa));

	return (NULL);
}

static int
child_walker(psinfo_t *psp, lwpsinfo_t *lsp __unused, void *arg)
{
	pid_t parent = *(pid_t *)arg;

	if (psp->pr_ppid != parent)
		return (0);

	child_pid = psp->pr_pid;
	return (1);
}

/*
 * Wait for the spawn child to come into existence, proving that the
 * spawning thread has entered spawn(2). The child cannot complete the
 * spawn until the FIFO gains a writer, so once the child exists the
 * spawning thread is parked waiting for it.
 */
static bool
wait_for_child(void)
{
	pid_t self = getpid();

	for (int i = 0; i < 10000; i++) {
		int found = proc_walk(child_walker, &self, PR_WALK_PROC);

		if (found == -1)
			err(EXIT_FAILURE, "could not walk /proc");
		if (found != 0)
			return (true);
		(void) usleep(1000);
	}

	return (false);
}

/*
 * Open /proc/<pid>/ctl and issue a PCSTOP. /proc control operations on a
 * spawn(2) child that has not yet exec'd must be refused with EBUSY.
 */
static bool
expect_ctl_ebusy(pid_t pid)
{
	char path[MAXPATHLEN];
	long cmd = PCSTOP;
	bool ret = false;
	int fd;

	(void) snprintf(path, sizeof (path), "/proc/%" _PRIdID "/ctl", pid);
	if ((fd = open(path, O_WRONLY)) == -1) {
		warn("TEST FAILED: could not open %s", path);
		return (false);
	}

	if (write(fd, &cmd, sizeof (cmd)) != -1) {
		warnx("TEST FAILED: PCSTOP on a spawning child unexpectedly "
		    "succeeded");
	} else if (errno != EBUSY) {
		warn("TEST FAILED: PCSTOP returned an unexpected error");
	} else {
		ret = true;
	}

	VERIFY0(close(fd));
	return (ret);
}

static void
alarm_handler(int sig __unused)
{
}

int
main(void)
{
	struct sigaction sa = { .sa_handler = alarm_handler };
	pthread_t tid;
	int ret = EXIT_SUCCESS;
	int fd, status;
	pid_t pid;

	if (snprintf(fifopath, sizeof (fifopath),
	    "/tmp/posix_spawn_wait.%" _PRIdID, getpid()) >= sizeof (fifopath))
		errx(EXIT_FAILURE, "FIFO path too long");
	(void) unlink(fifopath);
	if (mkfifo(fifopath, 0600) != 0)
		err(EXIT_FAILURE, "could not create FIFO %s", fifopath);

	/* SIGALRM must interrupt, not restart, a blocked system call */
	VERIFY0(sigaction(SIGALRM, &sa, NULL));

	VERIFY0(pthread_create(&tid, NULL, spawn_thread, NULL));

	if (!wait_for_child()) {
		warnx("TEST FAILED: spawn child never appeared");
		ret = EXIT_FAILURE;
		goto release;
	}

	/*
	 * The child is now parked mid-spawn, before it has exec'd. A /proc
	 * control operation on it must be refused with EBUSY.
	 */
	if (expect_ctl_ebusy(child_pid)) {
		(void) printf("TEST PASSED: /proc control of a spawning child "
		    "refused with EBUSY\n");
	} else {
		ret = EXIT_FAILURE;
	}

	/*
	 * The spawning thread is now parked in spawn(2). A fork from this
	 * thread must still complete. The alarm is a watchdog so that if the
	 * fork blocks, SIGALRM interrupts it with EINTR rather than letting
	 * the test hang.
	 */
	(void) alarm(10);
	pid = fork();
	(void) alarm(0);

	switch (pid) {
	case -1:
		if (errno == EINTR) {
			warnx("TEST FAILED: fork blocked while a sibling "
			    "thread was in spawn(2)");
		} else {
			warn("TEST FAILED: fork failed");
		}
		ret = EXIT_FAILURE;
		break;
	case 0:
		_exit(0);
	default:
		if (waitpid(pid, &status, 0) != pid ||
		    !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
			warnx("TEST FAILED: fork child did not exit cleanly");
			ret = EXIT_FAILURE;
		} else {
			(void) printf("TEST PASSED: fork while sibling "
			    "thread blocked in spawn\n");
		}
		break;
	}

release:
	/*
	 * Release the spawn child: a writer completes the FIFO rendezvous
	 * and the child's file-action open returns.
	 */
	(void) alarm(30);
	if ((fd = open(fifopath, O_WRONLY)) == -1) {
		warnx("TEST FAILED: could not open FIFO for writing");
		(void) unlink(fifopath);
		return (EXIT_FAILURE);
	}
	(void) alarm(0);
	VERIFY0(close(fd));

	VERIFY0(pthread_join(tid, NULL));

	if (spawn_ret != 0) {
		warnx("TEST FAILED: posix_spawn returned %d (%s)",
		    spawn_ret, strerror(spawn_ret));
		ret = EXIT_FAILURE;
	} else if (waitpid(spawn_pid, &status, 0) != spawn_pid ||
	    !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
		warnx("TEST FAILED: spawned child status %#x", status);
		ret = EXIT_FAILURE;
	} else {
		(void) printf("TEST PASSED: spawn completed after the "
		    "child was released\n");
	}

	(void) unlink(fifopath);

	if (ret == EXIT_SUCCESS)
		(void) printf("All tests passed successfully!\n");

	return (ret);
}
