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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * SMBFS I/O Deamon (smbiod)
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/note.h>

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

#include <err.h>
#include <door.h>
#include <thread.h>

#include <netsmb/smb_lib.h>

#define	ALARM_TIME	30	/* sec. */
#define	EXIT_FAIL	1
#define	EXIT_OK		0

#if defined(DEBUG) || defined(__lint)
#define	DPRINT(...)	do \
{ \
	if (smb_debug) \
		fprintf(stderr, __VA_ARGS__); \
	_NOTE(CONSTCOND) \
} while (0)
#else
#define	DPRINT(...) ((void)0)
#endif

mutex_t	iod_mutex = DEFAULTMUTEX;
int iod_thr_count;	/* threads, excluding main */
int iod_terminating;

void iod_dispatch(void *cookie, char *argp, size_t argsz,
    door_desc_t *dp, uint_t n_desc);
int iod_newvc(smb_iod_ssn_t *clnt_ssn);
void * iod_work(void *arg);

int
main(int argc, char **argv)
{
	static const int door_attrs =
	    DOOR_REFUSE_DESC | DOOR_NO_CANCEL;
	sigset_t oldmask, tmpmask;
	char *env, *door_path = NULL;
	int door_fd = -1, tmp_fd = -1;
	int err, i, sig;
	int rc = EXIT_FAIL;

	/* Debugging support. */
	if ((env = getenv("SMBFS_DEBUG")) != NULL) {
		smb_debug = atoi(env);
		if (smb_debug < 1)
			smb_debug = 1;
	}

	/*
	 * Find out if an IOD is already running.
	 * If so, we lost a harmless startup race.
	 * An IOD did start, so exit success.
	 */
	err = smb_iod_open_door(&door_fd);
	if (err == 0) {
		close(door_fd);
		door_fd = -1;
		DPRINT("main: already running\n");
		exit(EXIT_OK);
	}

	/*
	 * Create a file for the door.
	 */
	door_path = smb_iod_door_path();
	unlink(door_path);
	tmp_fd = open(door_path, O_RDWR|O_CREAT|O_EXCL, 0600);
	if (tmp_fd < 0) {
		perror(door_path);
		exit(EXIT_FAIL);
	}
	close(tmp_fd);
	tmp_fd = -1;


	/*
	 * Close FDs 0,1,2 so we don't have a TTY, and
	 * re-open them on /dev/null so they won't be
	 * used for device handles (etc.) later, and
	 * we don't have to worry about printf calls
	 * or whatever going to these FDs.
	 */
	for (i = 0; i < 3; i++) {
		/* Exception: If smb_debug, keep stderr */
		if (smb_debug && i == 2)
			break;
		close(i);
		tmp_fd = open("/dev/null", O_RDWR);
		if (tmp_fd < 0)
			perror("/dev/null");
		if (tmp_fd != i)
			DPRINT("Open /dev/null - wrong fd?\n");
	}

	/*
	 * Become session leader.
	 */
	setsid();

	/*
	 * Create door service threads with signals blocked.
	 */
	sigfillset(&tmpmask);
	sigprocmask(SIG_BLOCK, &tmpmask, &oldmask);

	/* Setup the door service. */
	door_fd = door_create(iod_dispatch, NULL, door_attrs);
	if (door_fd < 0) {
		fprintf(stderr, "%s: door_create failed\n", argv[0]);
		rc = EXIT_FAIL;
		goto errout;
	}
	fdetach(door_path);
	if (fattach(door_fd, door_path) < 0) {
		fprintf(stderr, "%s: fattach failed\n", argv[0]);
		rc = EXIT_FAIL;
		goto errout;
	}

	/*
	 * Post the initial alarm, and then just
	 * wait for signals.
	 */
	alarm(ALARM_TIME);
again:
	sig = sigwait(&tmpmask);
	DPRINT("main: sig=%d\n", sig);

	/*
	 * If a door call races with the alarm, ignore the alarm.
	 * It will be rescheduled when the threads go away.
	 */
	mutex_lock(&iod_mutex);
	if (sig == SIGALRM && iod_thr_count > 0) {
		mutex_unlock(&iod_mutex);
		goto again;
	}
	iod_terminating = 1;
	mutex_unlock(&iod_mutex);
	rc = EXIT_OK;

errout:
	fdetach(door_path);
	door_revoke(door_fd);
	door_fd = -1;
	unlink(door_path);

	return (rc);
}

/*ARGSUSED*/
void
iod_dispatch(void *cookie, char *argp, size_t argsz,
    door_desc_t *dp, uint_t n_desc)
{
	smb_iod_ssn_t *ssn;
	ucred_t *ucred;
	uid_t cl_uid;
	int rc;

	/*
	 * Verify that the calling process has the same UID.
	 * Paranoia:  The door we created has mode 0600, so
	 * this check is probably redundant.
	 */
	ucred = NULL;
	if (door_ucred(&ucred) != 0) {
		rc = EACCES;
		goto out;
	}
	cl_uid = ucred_getruid(ucred);
	ucred_free(ucred);
	ucred = NULL;
	if (cl_uid != getuid()) {
		DPRINT("iod_dispatch: wrong UID\n");
		rc = EACCES;
		goto out;
	}

	/*
	 * The library uses a NULL arg call to check if
	 * the deamon is running.  Just return zero.
	 */
	if (argp == NULL) {
		rc = 0;
		goto out;
	}

	/*
	 * Otherwise, the arg must be the (fixed size)
	 * smb_iod_ssn_t
	 */
	if (argsz != sizeof (*ssn)) {
		rc = EINVAL;
		goto out;
	}

	mutex_lock(&iod_mutex);
	if (iod_terminating) {
		mutex_unlock(&iod_mutex);
		DPRINT("iod_dispatch: terminating\n");
		rc = EINTR;
		goto out;
	}
	if (iod_thr_count++ == 0) {
		alarm(0);
		DPRINT("iod_dispatch: cancelled alarm\n");
	}
	mutex_unlock(&iod_mutex);

	ssn = (void *) argp;
	rc = iod_newvc(ssn);

	mutex_lock(&iod_mutex);
	if (--iod_thr_count == 0) {
		DPRINT("iod_dispatch: schedule alarm\n");
		alarm(ALARM_TIME);
	}
	mutex_unlock(&iod_mutex);

out:
	door_return((void *)&rc, sizeof (rc), NULL, 0);
}

/*
 * Try making a connection with the server described by
 * the info in the smb_iod_ssn_t arg.  If successful,
 * start an IOD thread to service it, then return to
 * the client side of the door.
 */
int
iod_newvc(smb_iod_ssn_t *clnt_ssn)
{
	smb_ctx_t *ctx;
	thread_t tid;
	int err;


	/*
	 * This needs to essentially "clone" the smb_ctx_t
	 * from the client side of the door, or at least
	 * as much of it as we need while creating a VC.
	 */
	err = smb_ctx_alloc(&ctx);
	if (err)
		return (err);
	bcopy(clnt_ssn, &ctx->ct_iod_ssn, sizeof (ctx->ct_iod_ssn));

	/*
	 * Do the initial connection setup here, so we can
	 * report the outcome to the door client.
	 */
	err = smb_iod_connect(ctx);
	if (err != 0)
		goto out;

	/*
	 * Create the driver session now, so we don't
	 * race with the door client findvc call.
	 */
	if ((err = smb_ctx_gethandle(ctx)) != 0)
		goto out;
	if (ioctl(ctx->ct_dev_fd, SMBIOC_SSN_CREATE, &ctx->ct_ssn) < 0) {
		err = errno;
		goto out;
	}

	/* The rest happens in the iod_work thread. */
	err = thr_create(NULL, 0, iod_work, ctx, THR_DETACHED, &tid);
	if (err == 0) {
		/*
		 * Given to the new thread.
		 * free at end of iod_work
		 */
		ctx = NULL;
	}

out:
	if (ctx)
		smb_ctx_free(ctx);

	return (err);
}

/*
 * Be the reader thread for some VC.
 *
 * This is started by a door call thread, which means
 * this is always at least the 2nd thread, therefore
 * it should never see thr_count==0 or terminating.
 */
void *
iod_work(void *arg)
{
	smb_ctx_t *ctx = arg;

	mutex_lock(&iod_mutex);
	if (iod_thr_count++ == 0) {
		alarm(0);
		DPRINT("iod_work: cancelled alarm\n");
	}
	mutex_unlock(&iod_mutex);

	(void) smb_iod_work(ctx);

	mutex_lock(&iod_mutex);
	if (--iod_thr_count == 0) {
		DPRINT("iod_work: schedule alarm\n");
		alarm(ALARM_TIME);
	}
	mutex_unlock(&iod_mutex);

	smb_ctx_free(ctx);
	return (NULL);
}
