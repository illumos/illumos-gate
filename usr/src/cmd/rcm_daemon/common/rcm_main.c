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

/*
 * Reconfiguration Coordination Daemon
 *
 * Accept RCM messages in the form of RCM events and process them
 * - to build and update the system resource map
 * - to allow clients to register/unregister for resource
 * - to allow dr initiators to offline a resource before removal
 * - to call into clients to perform suspend/offline actions
 *
 * The goal is to enable fully automated Dynamic Reconfiguration and better
 * DR information tracking.
 */

#include <librcm_event.h>

#include "rcm_impl.h"

/* will run in daemon mode if debug level < DEBUG_LEVEL_FORK */
#define	DEBUG_LEVEL_FORK	RCM_DEBUG

#define	DAEMON_LOCK_FILE "/var/run/rcm_daemon_lock"

static int hold_daemon_lock;
static int daemon_lock_fd;
static const char *daemon_lock_file = DAEMON_LOCK_FILE;

int debug_level = 0;
static int idle_timeout;
static int logflag = 0;
static char *prog;

static void usage(void);
static void catch_sighup(int);
static void catch_sigusr1(int);
static pid_t enter_daemon_lock(void);
static void exit_daemon_lock(void);

extern void init_poll_thread();
extern void cleanup_poll_thread();

/*
 * Print command line syntax for starting rcm_daemon
 */
static void
usage()
{
	(void) fprintf(stderr,
	    gettext("usage: %s [-d debug_level] [-t idle_timeout]\n"), prog);
	rcmd_exit(EINVAL);
}

/*
 * common cleanup/exit functions to ensure releasing locks
 */
static void
rcmd_cleanup(int status)
{
	if (status == 0) {
		rcm_log_message(RCM_INFO,
		    gettext("rcm_daemon normal exit\n"));
	} else {
		rcm_log_message(RCM_ERROR,
		    gettext("rcm_daemon exit: errno = %d\n"), status);
	}

	if (hold_daemon_lock) {
		exit_daemon_lock();
	}
}

void
rcmd_exit(int status)
{
	rcmd_cleanup(status);
	exit(status);
}

/*
 * When SIGHUP is received, reload modules at the next safe moment (when
 * there is no DR activity.
 */
void
catch_sighup(int signal __unused)
{
	rcm_log_message(RCM_INFO,
	    gettext("SIGHUP received, will exit when daemon is idle\n"));
	rcmd_thr_signal();
}

/*
 * When SIGUSR1 is received, exit the thread
 */
void
catch_sigusr1(int signal __unused)
{
	rcm_log_message(RCM_DEBUG, "SIGUSR1 received in thread %d\n",
	    thr_self());
	cleanup_poll_thread();
	thr_exit(NULL);
}

/*
 * Use an advisory lock to ensure that only one daemon process is
 * active at any point in time.
 */
static pid_t
enter_daemon_lock(void)
{
	struct flock lock;

	rcm_log_message(RCM_TRACE1,
	    "enter_daemon_lock: lock file = %s\n", daemon_lock_file);

	daemon_lock_fd = open(daemon_lock_file, O_CREAT|O_RDWR, 0644);
	if (daemon_lock_fd < 0) {
		rcm_log_message(RCM_ERROR, gettext("open(%s) - %s\n"),
		    daemon_lock_file, strerror(errno));
		rcmd_exit(errno);
	}

	lock.l_type = F_WRLCK;
	lock.l_whence = SEEK_SET;
	lock.l_start = 0;
	lock.l_len = 0;

	if (fcntl(daemon_lock_fd, F_SETLK, &lock) == 0) {
		hold_daemon_lock = 1;
		return (getpid());
	}

	/* failed to get lock, attempt to find lock owner */
	if ((errno == EAGAIN || errno == EDEADLK) &&
	    (fcntl(daemon_lock_fd, F_GETLK, &lock) == 0)) {
		return (lock.l_pid);
	}

	/* die a horrible death */
	rcm_log_message(RCM_ERROR, gettext("lock(%s) - %s"), daemon_lock_file,
	    strerror(errno));
	exit(errno);
	/*NOTREACHED*/
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
		rcm_log_message(RCM_ERROR, gettext("unlock(%s) - %s"),
		    daemon_lock_file, strerror(errno));
	}

	(void) close(daemon_lock_fd);
}

/*PRINTFLIKE2*/
static void
rcm_log_msg_impl(int level, char *message, va_list ap)
{
	int log_level;

	if (!logflag) {
		/*
		 * RCM_ERROR goes to stderr, others go to stdout
		 */
		FILE *out = (level <= RCM_ERROR) ? stderr : stdout;
		(void) vfprintf(out, message, ap);
		return;
	}

	/*
	 * translate RCM_* to LOG_*
	 */
	switch (level) {
	case RCM_ERROR:
		log_level = LOG_ERR;
		break;

	case RCM_WARNING:
		log_level = LOG_WARNING;
		break;

	case RCM_NOTICE:
		log_level = LOG_NOTICE;
		break;

	case RCM_INFO:
		log_level = LOG_INFO;
		break;

	case RCM_DEBUG:
		log_level = LOG_DEBUG;
		break;

	default:
		/*
		 * Don't log RCM_TRACEn messages
		 */
		return;
	}

	(void) vsyslog(log_level, message, ap);
}

/*
 * print error messages to the terminal or to syslog
 */
void
rcm_log_message(int level, char *message, ...)
{
	va_list ap;

	if (level > debug_level) {
		return;
	}

	va_start(ap, message);
	rcm_log_msg_impl(level, message, ap);
	va_end(ap);
}

/*
 * Print error messages to the terminal or to syslog.
 * Same as rcm_log_message except that it does not check for
 * level > debug_level
 * allowing callers to override the global debug_level.
 */
void
rcm_log_msg(int level, char *message, ...)
{
	va_list ap;

	va_start(ap, message);
	rcm_log_msg_impl(level, message, ap);
	va_end(ap);
}

/*
 * grab daemon_lock and direct messages to syslog
 */
static void
detachfromtty()
{
	(void) chdir("/");
	(void) setsid();
	(void) close(0);
	(void) close(1);
	(void) close(2);
	(void) open("/dev/null", O_RDWR, 0);
	(void) dup2(0, 1);
	(void) dup2(0, 2);
	openlog(prog, LOG_PID, LOG_DAEMON);
	logflag = 1;
}

int
main(int argc, char **argv)
{
	int c;
	pid_t pid;
	extern char *optarg;
	sigset_t mask;
	struct sigaction act;

	(void) setlocale(LC_ALL, "");
#ifndef	TEXT_DOMAIN
#define	TEXT_DOMAIN	"SYS_TEST"
#endif
	(void) textdomain(TEXT_DOMAIN);

	if ((prog = strrchr(argv[0], '/')) == NULL) {
		prog = argv[0];
	} else {
		prog++;
	}

	(void) enable_extended_FILE_stdio(-1, -1);

	/*
	 * process arguments
	 */
	if (argc > 3) {
		usage();
	}
	while ((c = getopt(argc, argv, "d:t:")) != EOF) {
		switch (c) {
		case 'd':
			debug_level = atoi(optarg);
			break;
		case 't':
			idle_timeout = atoi(optarg);
			break;
		case '?':
		default:
			usage();
			/*NOTREACHED*/
		}
	}

	/*
	 * Check permission
	 */
	if (getuid() != 0) {
		(void) fprintf(stderr, gettext("Must be root to run %s\n"),
		    prog);
		exit(EPERM);
	}

	/*
	 * When rcm_daemon is started by a call to librcm, it inherits file
	 * descriptors from the DR initiator making a call. The file
	 * descriptors may correspond to devices that can be removed by DR.
	 * Since keeping them remain opened is problematic, close everything
	 * but stdin/stdout/stderr.
	 */
	closefrom(3);

	/*
	 * When rcm_daemon is started by the caller, it will inherit the
	 * signal block mask.  We unblock all signals to make sure the
	 * signal handling will work normally.
	 */
	(void) sigfillset(&mask);
	(void) thr_sigsetmask(SIG_UNBLOCK, &mask, NULL);

	/*
	 * block SIGUSR1, use it for killing specific threads
	 */
	(void) sigemptyset(&mask);
	(void) sigaddset(&mask, SIGUSR1);
	(void) thr_sigsetmask(SIG_BLOCK, &mask, NULL);

	/*
	 * Setup signal handlers for SIGHUP and SIGUSR1
	 * SIGHUP - causes a "delayed" daemon exit, effectively the same
	 *	as a daemon restart.
	 * SIGUSR1 - causes a thr_exit(). Unblocked in selected threads.
	 */
	act.sa_flags = 0;
	act.sa_handler = catch_sighup;
	(void) sigaction(SIGHUP, &act, NULL);
	act.sa_handler = catch_sigusr1;
	(void) sigaction(SIGUSR1, &act, NULL);

	/*
	 * ignore SIGPIPE so that the rcm daemon does not exit when it
	 * attempts to read or write from a pipe whose corresponding
	 * rcm script process exited.
	 */
	act.sa_handler = SIG_IGN;
	(void) sigaction(SIGPIPE, &act, NULL);

	/*
	 * run in daemon mode
	 */
	if (debug_level < DEBUG_LEVEL_FORK) {
		if (fork()) {
			exit(0);
		}
		detachfromtty();
	}

	/* only one daemon can run at a time */
	if ((pid = enter_daemon_lock()) != getpid()) {
		rcm_log_message(RCM_DEBUG, "%s pid %d already running\n",
		    prog, pid);
		exit(EDEADLK);
	}

	rcm_log_message(RCM_TRACE1, "%s started, debug level = %d\n",
	    prog, debug_level);

	/*
	 * Set daemon state to block RCM requests before rcm_daemon is
	 * fully initialized. See rcmd_thr_incr().
	 */
	rcmd_set_state(RCMD_INIT);

	/*
	 * create rcm_daemon door and set permission to 0400
	 */
	if (create_event_service(RCM_SERVICE_DOOR, event_service) == -1) {
		rcm_log_message(RCM_ERROR,
		    gettext("cannot create door service: %s\n"),
		    strerror(errno));
		rcmd_exit(errno);
	}
	(void) chmod(RCM_SERVICE_DOOR, S_IRUSR);

	init_poll_thread(); /* initialize poll thread related data */

	/*
	 * Initialize database by asking modules to register.
	 */
	rcmd_db_init();

	/*
	 * Initialize locking, including lock recovery in the event of
	 * unexpected daemon failure.
	 */
	rcmd_lock_init();

	/*
	 * Start accepting normal requests
	 */
	rcmd_set_state(RCMD_NORMAL);

	/*
	 * Start cleanup thread
	 */
	rcmd_db_clean();

	/*
	 * Loop within daemon and return after a period of inactivity.
	 */
	rcmd_start_timer(idle_timeout);

	rcmd_cleanup(0);
	return (0);
}
