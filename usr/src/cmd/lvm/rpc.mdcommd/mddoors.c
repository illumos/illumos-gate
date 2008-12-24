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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <door.h>
#include <locale.h>
#include <meta.h>
#include <strings.h>
#include <syslog.h>

static pid_t enter_daemon_lock(void);
static void exit_daemon_lock(void);
#define	DAEMON_LOCK_FILE "/var/run/.mddoors.lock"

static int hold_daemon_lock;
static const char *daemon_lock_file = DAEMON_LOCK_FILE;
static int daemon_lock_fd;

void
daemon_cleanup()
{
	if (hold_daemon_lock) {
		meta_mirror_resync_block_all();
		exit_daemon_lock();
	}
}

/*
 * Use an advisory lock to ensure that only one daemon process is
 * active at any point in time.
 */
static pid_t
enter_daemon_lock(void)
{
	struct flock	lock;

	daemon_lock_fd = open(daemon_lock_file, O_CREAT|O_RDWR, 0644);

	if (daemon_lock_fd < 0) {
		exit(-1);
	}

	lock.l_type = F_WRLCK;
	lock.l_whence = SEEK_SET;
	lock.l_start = 0;
	lock.l_len = 0;

	if (fcntl(daemon_lock_fd, F_SETLK, &lock) == -1) {

		if (errno == EAGAIN || errno == EDEADLK) {

			if (fcntl(daemon_lock_fd, F_GETLK, &lock) == -1) {
				exit(1);
			}
			return (lock.l_pid);
		}
	}
	hold_daemon_lock = 1;
	return (getpid());
}


/*
 * Drop the advisory daemon lock, close lock file
 */
static void
exit_daemon_lock(void)
{
	struct flock lock;

	lock.l_type = F_UNLCK;
	lock.l_whence = SEEK_SET;
	lock.l_start = 0;
	lock.l_len = 0;

	if (fcntl(daemon_lock_fd, F_SETLK, &lock) == -1) {
		syslog(LOG_DAEMON | LOG_DEBUG, gettext("unlock(%s) - %s"),
		    daemon_lock_file, strerror(errno));
		return;
	}

	if (close(daemon_lock_fd) == -1) {
		syslog(LOG_DAEMON | LOG_DEBUG,
		    gettext("close(%s) failed - %s\n"),
		    daemon_lock_file, strerror(errno));
		return;
	}
	unlink(daemon_lock_file);
}

/*
 * Purpose of this routine is to accept a message from the local kernel and
 * send this message using rpc to the master node.
 * when an ok comes from the master we call door_return()
 */

/* ARGSUSED */
static void
door2rpc(void *cookie,		/* required by the doors infrastructure */
	char *argp,
	size_t arg_size,	/* required by the doors infrastructure */
	door_desc_t *dp,	/* required by the doors infrastructure */
	uint_t n_desc)		/* required by the doors infrastructure */
{
	int		err;
	int		size;
	md_error_t	ep = mdnullerror;
	md_mn_result_t	*result = NULL;
	md_mn_kresult_t	kresult;

	md_mn_kmsg_t *kmsg = (md_mn_kmsg_t *)(void *)argp;
	err = mdmn_send_message(kmsg->kmsg_setno, kmsg->kmsg_type,
	    kmsg->kmsg_flags, kmsg->kmsg_recipient, (char *)&(kmsg->kmsg_data),
	    kmsg->kmsg_size, &result, &ep);

	if (result == NULL) {
		kresult.kmmr_comm_state = MDMNE_RPC_FAIL;
	} else {
		kresult.kmmr_comm_state = result->mmr_comm_state;
		if (err == 0) {
			kresult.kmmr_msgtype = result->mmr_msgtype;
			kresult.kmmr_flags = result->mmr_flags;
			kresult.kmmr_exitval = result->mmr_exitval;
			kresult.kmmr_failing_node = result->mmr_failing_node;
			size = result->mmr_out_size;
			if (size > 0) {
				/* This is the max data we can transfer, here */
				if (size > MDMN_MAX_KRES_DATA) {
					size = MDMN_MAX_KRES_DATA;
				}
				bcopy(result->mmr_out, &(kresult.kmmr_res_data),
				    size);
				kresult.kmmr_res_size = size;
			} else {
				kresult.kmmr_res_size = 0;
			}
		}
		free_result(result);
	}

	door_return((char *)&kresult, sizeof (md_mn_kresult_t), NULL, 0);
}


/* ARGSUSED */
int
main(void)
{

	int		i;
	int		mdmn_door_handle;
	pid_t		pid;
	int		size;
	md_error_t	ep = mdnullerror;
	struct rlimit	rl;

	/*
	 * Get the locale set up before calling any other routines
	 * with messages to ouput.  Just in case we're not in a build
	 * environment, make sure that TEXT_DOMAIN gets set to
	 * something.
	 */
#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN "SYS_TEST"
#endif
	(void) setlocale(LC_ALL, "");
	(void) textdomain(TEXT_DOMAIN);

	openlog("mddoors", LOG_PID, LOG_DAEMON);

	/* here beginneth the daemonizing code */
	pid = fork();
	if (pid < 0) {
		syslog(LOG_DAEMON | LOG_ERR, gettext("Cannot fork"));
		exit(1);
	}

	if (pid) {
		exit(0);
	}

	/*
	 * Only one daemon can run at a time.
	 * If another instance is already running, this is not an error.
	 */
	if ((pid = enter_daemon_lock()) != getpid()) {
		exit(0);
	}

	rl.rlim_max = 0;
	getrlimit(RLIMIT_NOFILE, &rl);
	if ((size = rl.rlim_max) == 0) {
		syslog(LOG_DAEMON | LOG_ERR, gettext("Cannot getrlimit"));
		exit(1);
	}

	for (i = 0; i < size; i++) {
		if (i == daemon_lock_fd)
			continue;
		(void) close(i);
	}


	i = open("/dev/null", 2);
	(void) dup2(i, 1);
	(void) dup2(i, 2);
	setsid();

	/* here endeth the daemonizing code */

	/* Block out the usual signals so we don't get killed unintentionally */
	(void) signal(SIGHUP, SIG_IGN);
	(void) signal(SIGINT, SIG_IGN);
	(void) signal(SIGQUIT, SIG_IGN);
	(void) signal(SIGTERM, SIG_IGN);

	atexit(daemon_cleanup);

	/* Resume any previously blocked resync */
	meta_mirror_resync_unblock_all();

	/*
	 * At this point we are single threaded.
	 * We give mdmn_send_message() a chance to initialize safely.
	 */
	(void) mdmn_send_message(0, 0, 0, 0, 0, 0, 0, 0);

	/* setup the door handle */
	mdmn_door_handle = door_create(door2rpc, NULL,
	    DOOR_REFUSE_DESC | DOOR_NO_CANCEL);
	if (mdmn_door_handle == -1) {
		perror(gettext("door_create failed"));
		syslog(LOG_DAEMON | LOG_ERR, gettext("door_create failed"));
		exit(1);
	}

	if (metaioctl(MD_MN_SET_DOORH, &mdmn_door_handle, &ep,
	    "mddoors") != 0) {
		syslog(LOG_DAEMON | LOG_DEBUG, gettext(
		    "Couldn't set door handle"));
		exit(1);
	}

	(void) pause();
	syslog(LOG_DAEMON | LOG_ERR, gettext(
	    "Unexpected exit from pause()"));
	return (1);
}
