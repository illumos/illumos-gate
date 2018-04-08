/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */

/*
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*
 * SMBFS I/O Daemon (SMF service)
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/note.h>
#include <sys/queue.h>

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <synch.h>
#include <time.h>
#include <unistd.h>
#include <ucred.h>
#include <wait.h>
#include <priv_utils.h>
#include <err.h>
#include <door.h>
#include <libscf.h>
#include <locale.h>
#include <thread.h>
#include <assert.h>

#include <netsmb/smb_lib.h>

static boolean_t d_flag = B_FALSE;

/* Keep a list of child processes. */
typedef struct _child {
	LIST_ENTRY(_child) list;
	pid_t pid;
	uid_t uid;
} child_t;
static LIST_HEAD(, _child) child_list = { 0 };
mutex_t	cl_mutex = DEFAULTMUTEX;

static const char smbiod_path[] = "/usr/lib/smbfs/smbiod";
static const char door_path[] = SMBIOD_SVC_DOOR;

void svc_dispatch(void *cookie, char *argp, size_t argsz,
    door_desc_t *dp, uint_t n_desc);
static int cmd_start(uid_t uid, gid_t gid);
static int new_child(uid_t uid, gid_t gid);
static void svc_sigchld(void);
static void child_gone(uid_t, pid_t, int);
static void svc_cleanup(void);

static child_t *
child_find_by_pid(pid_t pid)
{
	child_t *cp;

	assert(MUTEX_HELD(&cl_mutex));
	LIST_FOREACH(cp, &child_list, list) {
		if (cp->pid == pid)
			return (cp);
	}
	return (NULL);
}

static child_t *
child_find_by_uid(uid_t uid)
{
	child_t *cp;

	assert(MUTEX_HELD(&cl_mutex));
	LIST_FOREACH(cp, &child_list, list) {
		if (cp->uid == uid)
			return (cp);
	}
	return (NULL);
}

/*
 * Find out if the service is already running.
 * Return: true, false.
 */
static boolean_t
already_running(void)
{
	door_info_t info;
	int fd, rc;

	if ((fd = open(door_path, O_RDONLY)) < 0)
		return (B_FALSE);

	rc = door_info(fd, &info);
	close(fd);
	if (rc < 0)
		return (B_FALSE);

	return (B_TRUE);
}

/*
 * This function will fork off a child process,
 * from which only the child will return.
 *
 * The parent exit status is taken as the SMF start method
 * success or failure, so the parent waits (via pipe read)
 * for the child to finish initialization before it exits.
 * Use SMF error codes only on exit.
 */
static int
daemonize_init(void)
{
	int pid, st;
	int pfds[2];

	chdir("/");

	if (pipe(pfds) < 0) {
		perror("pipe");
		exit(SMF_EXIT_ERR_FATAL);
	}
	if ((pid = fork1()) == -1) {
		perror("fork");
		exit(SMF_EXIT_ERR_FATAL);
	}

	/*
	 * If we're the parent process, wait for either the child to send us
	 * the appropriate exit status over the pipe or for the read to fail
	 * (presumably with 0 for EOF if our child terminated abnormally).
	 * If the read fails, exit with either the child's exit status if it
	 * exited or with SMF_EXIT_ERR_FATAL if it died from a fatal signal.
	 */
	if (pid != 0) {
		/* parent */
		close(pfds[1]);
		if (read(pfds[0], &st, sizeof (st)) == sizeof (st))
			_exit(st);
		if (waitpid(pid, &st, 0) == pid && WIFEXITED(st))
			_exit(WEXITSTATUS(st));
		_exit(SMF_EXIT_ERR_FATAL);
	}

	/* child */
	close(pfds[0]);

	return (pfds[1]);
}

static void
daemonize_fini(int pfd, int rc)
{
	/* Tell parent we're ready. */
	(void) write(pfd, &rc, sizeof (rc));
	close(pfd);
}

int
main(int argc, char **argv)
{
	sigset_t oldmask, tmpmask;
	struct sigaction sa;
	struct rlimit rl;
	int door_fd = -1, tmp_fd = -1, pfd = -1;
	int c, sig;
	int rc = SMF_EXIT_ERR_FATAL;
	boolean_t created = B_FALSE, attached = B_FALSE;

	/* set locale and text domain for i18n */
	(void) setlocale(LC_ALL, "");
	(void) textdomain(TEXT_DOMAIN);

	while ((c = getopt(argc, argv, "d")) != -1) {
		switch (c) {
		case 'd':
			/* Do debug messages. */
			d_flag = B_TRUE;
			break;
		default:
			fprintf(stderr, "Usage: %s [-d]\n", argv[0]);
			return (SMF_EXIT_ERR_CONFIG);
		}
	}

	if (already_running()) {
		fprintf(stderr, "%s: already running", argv[0]);
		return (rc);
	}

	/*
	 * Raise the fd limit to max
	 * errors here are non-fatal
	 */
	if (getrlimit(RLIMIT_NOFILE, &rl) != 0) {
		fprintf(stderr, "getrlimit failed, err %d\n", errno);
	} else if (rl.rlim_cur < rl.rlim_max) {
		rl.rlim_cur = rl.rlim_max;
		if (setrlimit(RLIMIT_NOFILE, &rl) != 0)
			fprintf(stderr, "setrlimit "
			    "RLIMIT_NOFILE %d, err %d",
			    (int)rl.rlim_cur, errno);
	}

	/*
	 * Want all signals blocked, as we're doing
	 * synchronous delivery via sigwait below.
	 */
	sigfillset(&tmpmask);
	sigprocmask(SIG_BLOCK, &tmpmask, &oldmask);

	/*
	 * Do want SIGCHLD, and will waitpid().
	 */
	sa.sa_flags = SA_NOCLDSTOP;
	sa.sa_handler = SIG_DFL;
	sigemptyset(&sa.sa_mask);
	sigaction(SIGCHLD, &sa, NULL);

	/*
	 * Daemonize, unless debugging.
	 */
	if (d_flag) {
		/* debug: run in foregound (not a service) */
		putenv("SMBFS_DEBUG=1");
	} else {
		/* Non-debug: start daemon in the background. */
		pfd = daemonize_init();
	}

	/*
	 * Create directory for all smbiod doors.
	 */
	if ((mkdir(SMBIOD_RUNDIR, 0755) < 0) && errno != EEXIST) {
		perror(SMBIOD_RUNDIR);
		goto out;
	}

	/*
	 * Create a file for the main service door.
	 */
	unlink(door_path);
	tmp_fd = open(door_path, O_RDWR|O_CREAT|O_EXCL, 0644);
	if (tmp_fd < 0) {
		perror(door_path);
		goto out;
	}
	close(tmp_fd);
	tmp_fd = -1;
	created = B_TRUE;

	/* Setup the door service. */
	door_fd = door_create(svc_dispatch, NULL,
	    DOOR_REFUSE_DESC | DOOR_NO_CANCEL);
	if (door_fd == -1) {
		perror("svc door_create");
		goto out;
	}
	fdetach(door_path);
	if (fattach(door_fd, door_path) < 0) {
		fprintf(stderr, "%s: fattach failed, %s\n",
		    door_path, strerror(errno));
		goto out;
	}
	attached = B_TRUE;

	/*
	 * Initializations done.  Tell start method we're up.
	 */
	rc = SMF_EXIT_OK;
	if (pfd != -1) {
		daemonize_fini(pfd, rc);
		pfd = -1;
	}

	/*
	 * Main thread just waits for signals.
	 */
again:
	sig = sigwait(&tmpmask);
	if (d_flag)
		fprintf(stderr, "main: sig=%d\n", sig);
	switch (sig) {
	case SIGINT:
	case SIGTERM:
		/*
		 * The whole process contract gets a SIGTERM
		 * at once.  Give children a chance to exit
		 * so we can do normal SIGCHLD cleanup.
		 * Prevent new door_open calls.
		 */
		fdetach(door_path);
		attached = B_FALSE;
		alarm(2);
		goto again;
	case SIGALRM:
		break;	/* normal termination */
	case SIGCHLD:
		svc_sigchld();
		goto again;
	case SIGCONT:
		goto again;
	default:
		/* Unexpected signal. */
		fprintf(stderr, "svc_main: unexpected sig=%d\n", sig);
		break;
	}

out:
	if (attached)
		fdetach(door_path);
	if (door_fd != -1)
		door_revoke(door_fd);
	if (created)
		unlink(door_path);

	/* NB: door threads gone now. */
	svc_cleanup();

	/* If startup error, report to parent. */
	if (pfd != -1)
		daemonize_fini(pfd, rc);

	return (rc);
}

/*ARGSUSED*/
void
svc_dispatch(void *cookie, char *argp, size_t argsz,
    door_desc_t *dp, uint_t n_desc)
{
	ucred_t *ucred = NULL;
	uid_t uid;
	gid_t gid;
	int32_t cmd, rc;

	/*
	 * Allow a NULL arg call to check if this
	 * daemon is running.  Just return zero.
	 */
	if (argp == NULL) {
		rc = 0;
		goto out;
	}

	/*
	 * Get the caller's credentials.
	 * (from client side of door)
	 */
	if (door_ucred(&ucred) != 0) {
		rc = EACCES;
		goto out;
	}
	uid = ucred_getruid(ucred);
	gid = ucred_getrgid(ucred);

	/*
	 * Arg is just an int command code.
	 * Reply is also an int.
	 */
	if (argsz != sizeof (cmd)) {
		rc = EINVAL;
		goto out;
	}
	bcopy(argp, &cmd, sizeof (cmd));
	switch (cmd) {
	case SMBIOD_START:
		rc = cmd_start(uid, gid);
		break;
	default:
		rc = EINVAL;
		goto out;
	}

out:
	if (ucred != NULL)
		ucred_free(ucred);

	door_return((void *)&rc, sizeof (rc), NULL, 0);
}

/*
 * Start a per-user smbiod, if not already running.
 */
int
cmd_start(uid_t uid, gid_t gid)
{
	char door_file[64];
	child_t *cp;
	int pid, fd = -1;

	mutex_lock(&cl_mutex);
	cp = child_find_by_uid(uid);
	if (cp != NULL) {
		/* This UID already has an IOD. */
		mutex_unlock(&cl_mutex);
		if (d_flag) {
			fprintf(stderr, "cmd_start: uid %d"
			    " already has an iod\n", uid);
		}
		return (0);
	}

	/*
	 * OK, create a new child.
	 */
	cp = malloc(sizeof (*cp));
	if (cp == NULL) {
		mutex_unlock(&cl_mutex);
		return (ENOMEM);
	}
	cp->pid = 0; /* update below */
	cp->uid = uid;
	LIST_INSERT_HEAD(&child_list, cp, list);
	mutex_unlock(&cl_mutex);

	/*
	 * The child will not have permission to create or
	 * destroy files in SMBIOD_RUNDIR so do that here.
	 */
	snprintf(door_file, sizeof (door_file),
	    SMBIOD_USR_DOOR, cp->uid);
	unlink(door_file);
	fd = open(door_file, O_RDWR|O_CREAT|O_EXCL, 0600);
	if (fd < 0) {
		perror(door_file);
		goto errout;
	}
	if (fchown(fd, uid, gid) < 0) {
		perror(door_file);
		goto errout;
	}
	close(fd);
	fd = -1;

	if ((pid = fork1()) == -1) {
		perror("fork");
		goto errout;
	}
	if (pid == 0) {
		(void) new_child(uid, gid);
		_exit(1);
	}
	/* parent */
	cp->pid = pid;

	if (d_flag) {
		fprintf(stderr, "cmd_start: uid %d new iod, pid %d\n",
		    uid, pid);
	}

	return (0);

errout:
	if (fd != -1)
		close(fd);
	mutex_lock(&cl_mutex);
	LIST_REMOVE(cp, list);
	mutex_unlock(&cl_mutex);
	free(cp);
	return (errno);
}

/*
 * Assume the passed credentials (from the door client),
 * drop any extra privileges, and exec the per-user iod.
 */
static int
new_child(uid_t uid, gid_t gid)
{
	char *argv[2];
	int flags, rc;

	flags = PU_RESETGROUPS | PU_LIMITPRIVS | PU_INHERITPRIVS;
	rc = __init_daemon_priv(flags, uid, gid, PRIV_NET_ACCESS, NULL);
	if (rc != 0)
		return (errno);

	argv[0] = "smbiod";
	argv[1] = NULL;
	(void) execv(smbiod_path, argv);
	return (errno);
}

static void
svc_sigchld(void)
{
	child_t *cp;
	pid_t pid;
	int err, status, found = 0;

	mutex_lock(&cl_mutex);

	while ((pid = waitpid(-1, &status, WNOHANG)) > 0) {

		found++;
		if (d_flag)
			fprintf(stderr, "svc_sigchld: pid %d\n", (int)pid);

		cp = child_find_by_pid(pid);
		if (cp == NULL) {
			fprintf(stderr, "Unknown pid %d\n", (int)pid);
			continue;
		}
		child_gone(cp->uid, cp->pid, status);
		LIST_REMOVE(cp, list);
		free(cp);
	}
	err = errno;

	mutex_unlock(&cl_mutex);

	/* ECHILD is the normal end of loop. */
	if (pid < 0 && err != ECHILD)
		fprintf(stderr, "svc_sigchld: waitpid err %d\n", err);
	if (found == 0)
		fprintf(stderr, "svc_sigchld: no children?\n");
}

static void
child_gone(uid_t uid, pid_t pid, int status)
{
	char door_file[64];
	int x;

	if (d_flag)
		fprintf(stderr, "child_gone: uid %d pid %d\n",
		    uid, (int)pid);

	snprintf(door_file, sizeof (door_file),
	    SMBIOD_RUNDIR "/%d", uid);
	unlink(door_file);

	if (WIFEXITED(status)) {
		x = WEXITSTATUS(status);
		if (x != 0) {
			fprintf(stderr,
			    "uid %d, pid %d exit %d\n",
			    uid, (int)pid, x);
		}
	}
	if (WIFSIGNALED(status)) {
		x = WTERMSIG(status);
		fprintf(stderr,
		    "uid %d, pid %d signal %d\n",
		    uid, (int)pid, x);
	}
}

/*
 * Final cleanup before exit.  Unlink child doors, etc.
 * Called while single threaded, so no locks needed here.
 * The list is normally empty by now due to svc_sigchld
 * calls during shutdown.  But in case there were any
 * straglers, do cleanup here.  Don't bother freeing any
 * list elements here, as we're exiting.
 */
static void
svc_cleanup(void)
{
	child_t *cp;

	LIST_FOREACH(cp, &child_list, list) {
		child_gone(cp->uid, cp->pid, 0);
	}
}
