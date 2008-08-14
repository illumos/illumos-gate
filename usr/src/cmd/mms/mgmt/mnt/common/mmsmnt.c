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

#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <libgen.h>
#include <errno.h>
#include <door.h>
#include <pthread.h>
#include <signal.h>
#include <dirent.h>
#include <string.h>
#include <rpc/xdr.h>
#include <stdarg.h>

#include <libnvpair.h>
#include "mms.h"
#include "mms_mgmt.h"
#include "mgmt_util.h"

/*
 *  MMS Mount service daemon.
 *
 *  Uses the "door" interface for inter-process communication.
 */

/* structure for session list */
typedef struct mnt_sess {
	void		*session;
	char		*volname;
	char		*library;
	char		*cartridge;
	char		*app;
	char		*localdev;
	struct mnt_sess	*next;
} mnt_sess_t;

/*  Function declarations */
static void *handle_signal(void *arg);
static void mntsvr(void *cookie, char *argp, size_t arg_size, door_desc_t *dp,
	uint_t n_desc);
static void log_err(const char *errpfx, const char *msg);
static void do_log_err(char *errpfx, char *fmt, ...);
static void * exit_idle(void *arg);
static int mount_vol(mmsmnt_arg_t *in);
static void incr_active(void);
static void decr_active(void);
static void add_session(mnt_sess_t *in);
static void remove_session(mmsmnt_arg_t *in, mnt_sess_t **sess);
static int unmount_vol(mmsmnt_arg_t *in);
static void free_sess(mnt_sess_t *in);

/*  Globals */
boolean_t		do_daemon = B_TRUE;
pthread_attr_t		pattr;
pthread_mutex_t		glock = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t		quitcond = PTHREAD_COND_INITIALIZER;
boolean_t		stopserver = B_FALSE;
char			*ourdoor = "/var/run/mmsmnt_door";
char			*ourlock = "/var/run/mmsmnt_door_lk";
mnt_sess_t		*sess_list = NULL;

/* session list lock */
pthread_rwlock_t	sesslk = PTHREAD_RWLOCK_INITIALIZER;

/* mutex and condition for activity */
pthread_mutex_t		mntmutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t		mntcond = PTHREAD_COND_INITIALIZER;
int			active = 0;

/* error log file */
static char		*errLog = "/var/log/mms/mmsmnt.log";
FILE			*errFilep = stderr;
pid_t			mntd_pid = -1;
static char		*timefmt = "%e %b %Y %T %Z";

/*
 *  This mount server process typically runs as an independent
 *  daemon.  For debugging purposes, use the "-d" option to run
 *  the server in the foreground.  "-d" is only available if the
 *  server has been compiled with -DDEBUG.
 *
 */
int
main(int argc, char *argv[])
{
	int		st;
	char		c;
	pid_t		pid;
	int		nullfd;
	sigset_t	mask;
	int		doorfd = -1;
	int		lockfd = -1;
	flock64_t	flk;
	pthread_t	tid;
	int		logfd = -1;
	char		*errpfx = "main";

	while ((c = getopt(argc, argv, "d")) != -1) {
		switch (c) {
			case 'd':
				do_daemon = B_FALSE;
				break;
			default:
				/* ignore invalid args */
				break;
		}
	}

	/* make sure we didn't inherit a weird creation mask */
	(void) umask(0);

	/* close any inherited file descriptors */
	closefrom(STDERR_FILENO + 1);

	nullfd = open("/dev/null", O_RDWR);

	/* and disassociate from our parent */
	if (do_daemon) {
		pid = fork();
		if (pid < 0) {
			(void) printf("Cannot fork process, exiting\n");
			exit(1);
		} else if (pid > 0) {
			/* parent exits now */
			exit(0);
		}
		/* become session leader */
		(void) setsid();

		/* set out working directory to something rational */
		(void) chdir("/var/mms/cores");
	}

	/* block most signals.  We only care about the die now ones */
	(void) sigfillset(&mask);

	/*
	 * if we're in debug mode, most likely in the debugger so
	 * allow SIGINT
	 */
	if (!do_daemon) {
		(void) sigdelset(&mask, SIGINT);
	}

	(void) pthread_sigmask(SIG_BLOCK, &mask, NULL);

	if (do_daemon) {
		/*
		 * One last fork to make sure we're really really
		 * not going to inherit a controlling terminal...
		 */
		pid = fork();
		if (pid != 0) {
			exit(0);
		};

		/* we're not using stdin/out/err */
		dup2(nullfd, STDIN_FILENO);
		dup2(nullfd, STDOUT_FILENO);
		dup2(nullfd, STDERR_FILENO);
	} else {
		/* assign stderr to stdout */
		dup2(STDOUT_FILENO, STDERR_FILENO);
	}

	/* initialize log - defaults to stderr if log can't be opened */
	mntd_pid = getpid();
	logfd = open64(errLog, O_RDWR|O_CREAT, 0744);
	if (logfd != -1) {
		errFilep = fdopen(logfd, "a+");
	}

	do_log_err(errpfx, "mmsmntd starting");

	mms_trace_open(errLog, MMS_ID_CLI, MMS_SEV_NOTICE, 5 * MEGA, 0, 0);

	/* all threads we create should be detached */
	(void) pthread_attr_init(&pattr);
	(void) pthread_attr_setdetachstate(&pattr, PTHREAD_CREATE_DETACHED);

	/* Set up a signal handling thread */
	(void) pthread_create(&tid, &pattr, handle_signal, NULL);

	/* start the activity thread */
	pthread_create(&tid, &pattr, exit_idle, NULL);

	/* lock so multiple processes don't start */
	lockfd = open(ourlock, O_WRONLY|O_CREAT, 0655);
	if (lockfd == -1) {
		do_log_err(errpfx, "Could not lock %s", ourdoor);
		return (errno);
	}

	memset(&flk, 0, sizeof (flock64_t));
	flk.l_type = F_WRLCK;
	flk.l_whence = SEEK_SET;

	st = fcntl(lockfd, F_SETLK64, &flk);
	if (st == -1) {
		if (errno == EAGAIN) {
			/* already locked */
			do_log_err(errpfx, "mmsmnt process already running");
			st = 0;
		}
		goto done;
	}

	/* open the doors! */
	doorfd = door_create(mntsvr, NULL, 0);
	if (doorfd == -1) {
		st = -1;
		goto done;
	}

	/*
	 * recreate the door itself.  If a previous process exited
	 * abnormally (core dump, whatever), the door won't be revoked
	 * and we won't be able to start a new process.  Yet another
	 * weird door-ism.  The locking above should prevent a door
	 * from being removed out from under a running process.
	 */
	unlink(ourdoor);
	st = mknod(ourdoor, 0655, 0);
	if (st == -1) {
		st = errno;
		do_log_err(errpfx, "Could not create door.");
		goto done;
	}

	st = fattach(doorfd, ourdoor);
	if (st == -1) {
		st = errno;
		if (st == EBUSY) {
			/* shouldn't happen - another process got here first */
			st = 0;
		} else {
			do_log_err(errpfx, "Could not attach to door %d", st);
		}
		goto done;
	}

	/* the mntsvr function now does all the work.  Sit and wait to exit */
	(void) pthread_mutex_lock(&glock);
	while (!stopserver) {
		(void) pthread_cond_wait(&quitcond, &glock);
	}
	(void) pthread_mutex_unlock(&glock);

done:
	do_log_err(errpfx, "mmsmnt exiting with status %d", st);

	/* don't let any more calls in */
	door_revoke(doorfd);

	if (lockfd != -1) {
		close(lockfd);
	}

	/* all done */
	return (st);
}

/* exit cleanly if we're told to stop */
static void *
handle_signal(void *arg)	/* ARGSUSED */
{
	int		count;
	int		st = 0;
#ifndef	__lint
	int		signum;
#endif	/* __lint */
	sigset_t	mask;

	(void) sigemptyset(&mask);
	(void) sigaddset(&mask, SIGINT);
	(void) sigaddset(&mask, SIGQUIT);
	(void) sigaddset(&mask, SIGTERM);

	(void) pthread_sigmask(SIG_UNBLOCK, &mask, NULL);

	/*
	 * wait forever, or until sigwait fails 10 times.  sigwait()
	 * shouldn't fail, but we don't want to be looping frantically
	 * if it does.
	 */
	for (count = 0; count < 10; count++) {
		/*
		 * for reasons I don't understand, lint is unhappy with
		 * the sigwait() function declaration in signal.h.
		 */
#ifndef __lint
		st = sigwait(&mask, &signum);
#endif
		if (st == 0) {
			break;
		}
	}

	if (st == 0) {
		/* we've been asked to exit */
		(void) pthread_mutex_lock(&glock);
		stopserver = B_TRUE;
		(void) pthread_mutex_unlock(&glock);
		(void) pthread_cond_broadcast(&quitcond);
	}

	return (NULL);
}

/* main dispatch function */
static void
mntsvr(
	void		*cookie,	/* ARGSUSED */
	char		*argp,
	size_t		arg_size,	/* ARGSUSED */
	door_desc_t	*dp,
	uint_t		n_desc)
{

	int			st;
	char			*errpfx = "mntsvr";
	/* LINTED [E_BAD_PTR_CAST_ALIGN] */
	mmsmnt_arg_t		*inarg = (mmsmnt_arg_t *)argp;

	incr_active();

	if (argp == NULL) {
		st = EINVAL;
		do_log_err(errpfx, "No arguments received");
		goto done;
	}

	if (inarg->op == 1) {
		st = mount_vol(inarg);
	} else if (inarg->op == 2) {
		st = unmount_vol(inarg);
	} else {
		st = EINVAL;
	}

done:
	if (st != 0) {
		do_log_err(errpfx, "Completed task type = %d, status = %d",
		    inarg->op, st);
	}

	inarg->st = st;

	decr_active();

	door_return((char *)inarg, arg_size, NULL, 0);
}

static int
unmount_vol(mmsmnt_arg_t *in)
{
	int		st;
	mnt_sess_t	*old = NULL;
	void		*response = NULL;
	char		tid[64];
	char		cmd[8192];

	if (!in) {
		return (EINVAL);
	}

	remove_session(in, &old);
	if (!old) {
		/* nothing to do, just return */
		return (0);
	}

	mms_gen_taskid(tid);
	snprintf(cmd, sizeof (cmd),
	    "unmount task['%s'] type[VOLUME] "
	    "match[and (streq(LIBRARY.'LibraryName' '%s') "
	    "streq(CARTRIDGE.'CartridgePCL' '%s'))] ",
	    tid, old->library, old->cartridge);
	if (in->cmd[0] != '\0') {
		strlcat(cmd, in->cmd, sizeof (cmd));
	}
	strlcat(cmd, ";", sizeof (cmd));

	/* use existing session to unmount */
	st = mms_mgmt_send_cmd(old->session, "", cmd, "unmount volume",
	    &response);

	free_sess(old);

	decr_active();

	return (st);
}

static void
add_session(mnt_sess_t *in)
{
	if (!in) {
		return;
	}

	pthread_rwlock_wrlock(&sesslk);
	in->next = sess_list;
	sess_list = in;
	pthread_rwlock_unlock(&sesslk);
}

static void
free_sess(mnt_sess_t *in)
{
	if (!in) {
		return;
	}

	if (in->volname) {
		free(in->volname);
	}

	if (in->cartridge) {
		free(in->cartridge);
	}

	if (in->library) {
		free(in->library);
	}

	if (in->session) {
		mms_goodbye(in->session, 0);
	}

	free(in);
}

static int
mount_vol(mmsmnt_arg_t *in)
{
	int		st;
	mnt_sess_t	*new = NULL;
	char		*val;
	void		*sess = NULL;
	void		*response = NULL;
	nvlist_t	*mntattrs = NULL;
	nvpair_t	*nvp = NULL;
	nvlist_t	*volattrs = NULL;
	char		*app = NULL;
	char		*inst = NULL;
	char		*pass = NULL;

	if ((!in) || (in->cmd[0] == '\0')) {
		return (EINVAL);
	}

	incr_active();

	if (in->app[0] != '\0') {
		app = in->app;
	}
	if (in->inst[0] != '\0') {
		inst = in->inst;
	}
	if (in->pass[0] != '\0') {
		pass = in->pass;
	}

	st = create_mm_clnt(app, inst, pass, NULL, &sess);
	if (st != 0) {
		goto done;
	}

	new = calloc(1, sizeof (mnt_sess_t));
	if (new == NULL) {
		st = ENOMEM;
		goto done;
	}
	new->volname = strdup(in->volname);
	new->cartridge = strdup(in->cartridge);
	new->library = strdup(in->library);

	st = mms_mgmt_send_cmd(sess, "", in->cmd, "mount volume", &response);
	if (st == 0) {
		st = mmp_get_nvattrs("VolumeName", B_FALSE, response,
		    &mntattrs);
		mms_free_rsp(response);
	}
	if (st != 0) {
		goto done;
	}

	new->session = sess;

	nvp = nvlist_next_nvpair(mntattrs, NULL);
	if (nvp == NULL) {
		/* should never happen! */
		st = ENOENT;
		goto done;
	}

	st = nvpair_value_nvlist(nvp, &volattrs);
	if (st != 0) {
		goto done;
	}

	st = nvlist_lookup_string(volattrs, "MountLogicalHandle", &val);
	if (st != 0) {
		goto done;
	}
	new->localdev = strdup(val);
	strlcat(in->devname, val, sizeof (in->devname));

	add_session(new);

done:
	if (st != 0) {
		if (sess) {
			mms_goodbye(sess, 0);
			new->session = NULL;
		}
		if (new) {
			free_sess(new);
		}
		decr_active();
	}

	return (st);

}

static void
remove_session(mmsmnt_arg_t *in, mnt_sess_t **sess)
{
	mnt_sess_t	*ent;
	mnt_sess_t	*prev = NULL;

	*sess = NULL;

	pthread_rwlock_wrlock(&sesslk);
	ent = sess_list;

	/* match on devname if available, else look for cartridge/library */
	while (ent != NULL) {
		if (in->devname[0] != '\0') {
			if (strcmp(ent->localdev, in->devname) == 0) {
				break;
			}
		}
		if ((strcmp(ent->library, in->library) == 0) &&
		    (strcmp(ent->cartridge, in->cartridge) == 0)) {
			break;
		}
		prev = ent;
		ent = ent->next;
	}

	if (ent) {
		if (!prev) {
			/* first on list */
			sess_list = ent->next;
		} else {
			prev->next = ent->next;
		}
		*sess = ent;
	}
	pthread_rwlock_unlock(&sesslk);
}

static void
log_err(
	const char	*errpfx,
	const char	*msg)
{
	char		timbuf[MAXPATHLEN];
	time_t		logtime;
	char		*pfxp = (char *)errpfx;
	struct tm	*tm = NULL;

	if (msg == NULL) {
		return;
	}

	if (pfxp == NULL) {
		pfxp = "";
	}

	logtime = time(NULL);
	tm = localtime(&logtime);
	(void) strftime(timbuf, sizeof (timbuf), timefmt, tm);
	(void) fprintf(errFilep, "%s [%ld] %s: %s\n", timbuf, mntd_pid,
	    pfxp, msg);
	(void) fflush(errFilep);
}

static void
do_log_err(char *errpfx, char *fmt, ...)
{
	va_list		ap;
	char		buf[2048];

	va_start(ap, fmt);
	/* LINTED [E_SEC_PRINTF_VAR_FMT] */
	vsnprintf(buf, sizeof (buf), fmt, ap);
	va_end(ap);

	log_err(errpfx, buf);
}

static void
incr_active(void)
{
	pthread_mutex_lock(&mntmutex);
	active++;
	pthread_cond_signal(&mntcond);
	pthread_mutex_unlock(&mntmutex);
}

static void
decr_active(void)
{
	pthread_mutex_lock(&mntmutex);
	active--;
	pthread_cond_signal(&mntcond);
	pthread_mutex_unlock(&mntmutex);
}

/*
 *  function to shut down this server if we timeout waiting for requests
 */
static void *
exit_idle(void *arg) /* ARGSUSED */
{
	struct timespec	ts;

	/* sleep for 1 minute waiting for activity after we first start */
	ts.tv_sec = 60;
	ts.tv_nsec = 0;

	nanosleep(&ts, NULL);

	pthread_mutex_lock(&mntmutex);
	while (active > 0) {
		pthread_cond_wait(&mntcond, &mntmutex);

		pthread_mutex_unlock(&mntmutex);
		/* 1 minute of idle time, only */
		ts.tv_sec = 60;
		ts.tv_nsec = 0;

		/* sleep for a little while */
		nanosleep(&ts, NULL);
		pthread_mutex_lock(&mntmutex);
	}
	/* signal exit */
	pthread_mutex_unlock(&mntmutex);
	sigsend(P_PID, getpid(), SIGTERM);

	return (NULL);
}
