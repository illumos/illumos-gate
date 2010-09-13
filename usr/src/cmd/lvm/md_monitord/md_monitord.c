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
 * probedev issues ioctls for all the metadevices
 */

#include "md_monitord.h"
#include <sdssc.h>

extern char queue_name[];
boolean_e issue_ioctl = True;


#define	DEBUG_LEVEL_FORK	9	/* will run in background at all */
					/* levels less than DEBUG_LEVEL_FORK */

/* function prototypes */
static void usage(void);
static void catch_sig(int);
static pid_t enter_daemon_lock(void);
static void exit_daemon_lock(void);
static void probe_all_devs(boolean_e, md_error_t *, boolean_e);

#define	DAEMON_LOCK_FILE "/etc/lvm/.mdmonitord.lock"

/*
 * Global variable
 */
mdsetname_t	*sp;

static int hold_daemon_lock;
static const char *daemon_lock_file = DAEMON_LOCK_FILE;
static int daemon_lock_fd;

static int		debug_level;
static int		logflag;
static char		*prog;
static struct itimerval	itimer;
static boolean_e	probe_started;	/* flag to indicate main is probing */

static void
usage() {
	(void) fprintf(stderr, gettext(
		"usage: mdmonitord [-d <debug_level>] [-t poll time]\n"
		    "higher debug levels get progressively more"
		    "detailed debug information.\n\n"
		    "mdmonitord will run in background if run"
		    "with a debug_level less than %d.\n"), DEBUG_LEVEL_FORK);
	exit(-1);
}


/* common exit function which ensures releasing locks */
void
monitord_exit(int status)
{
	monitord_print(1, gettext("exit status = %d\n"), status);

	monitord_print(8, "hold_daemon_lock %d\n", hold_daemon_lock);
	if (hold_daemon_lock) {
		exit_daemon_lock();
	}
	md_exit(sp, status);
}


/*
 * When SIGHUP is received, reload modules?
 */
void
catch_sig(int sig)
{
	boolean_e startup = False;
	md_error_t status = mdnullerror;
	boolean_e sig_verbose = True;

	if (sig == SIGALRM) {
		monitord_print(6, gettext("SIGALRM processing"));
		if (probe_started == True) {
			monitord_print(6, gettext(
			    " probe_started returning\n"));
			return;
		}
		monitord_print(6, gettext(
		    " starting probe from signal handler\n"));
		probe_all_devs(startup, &status, sig_verbose);
		(void) setitimer(ITIMER_REAL, &itimer, NULL);
	}
	if (sig == SIGHUP)
		monitord_exit(sig);
}

/*
 * Use an advisory lock to ensure that only one daemon process is
 * active at any point in time.
 */
static pid_t
check_daemon_lock(void)
{
	struct flock	lock;

	monitord_print(1, gettext("check_daemon_lock: lock file = %s\n"),
	    daemon_lock_file);

	daemon_lock_fd = open(daemon_lock_file, O_CREAT|O_RDWR, 0644);
	if (daemon_lock_fd < 0) {
		monitord_print(0, "open(%s) - %s\n", daemon_lock_file,
		    strerror(errno));
		monitord_exit(-1);
	}

	lock.l_type = F_WRLCK;
	lock.l_whence = SEEK_SET;
	lock.l_start = 0;
	lock.l_len = 0;

	if (fcntl(daemon_lock_fd, F_GETLK, &lock) == -1) {
		monitord_print(0, "lock(%s) - %s", daemon_lock_file,
		    strerror(errno));
		monitord_exit(-1);
	}

	return (lock.l_type == F_UNLCK ? 0 : lock.l_pid);
}

static pid_t
enter_daemon_lock(void)
{
	struct flock	lock;

	monitord_print(1, gettext(
	    "enter_daemon_lock: lock file = %s\n"), daemon_lock_file);

	daemon_lock_fd = open(daemon_lock_file, O_CREAT|O_RDWR, 0644);
	if (daemon_lock_fd < 0) {
		monitord_print(0, "open(%s) - %s\n",
		    daemon_lock_file, strerror(errno));
		monitord_exit(-1);
	}

	lock.l_type = F_WRLCK;
	lock.l_whence = SEEK_SET;
	lock.l_start = 0;
	lock.l_len = 0;

	if (fcntl(daemon_lock_fd, F_SETLK, &lock) == -1) {

		if (errno == EAGAIN || errno == EDEADLK) {

			if (fcntl(daemon_lock_fd, F_GETLK, &lock) == -1) {
				monitord_print(0, "lock(%s) - %s",
				    daemon_lock_file, strerror(errno));
				monitord_exit(-1);
			}

			return (lock.l_pid);
		}
	}
	hold_daemon_lock = 1;

	return (0);
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
		monitord_print(0, "unlock(%s) - %s",
		    daemon_lock_file, strerror(errno));
	}

	if (close(daemon_lock_fd) == -1) {
		monitord_print(0, "close(%s) failed - %s\n",
		    daemon_lock_file, strerror(errno));
		monitord_exit(-1);
	}
	(void) unlink(daemon_lock_file);
}


/*
 * print error messages to the terminal or to syslog
 */
/*PRINTFLIKE2*/
void
monitord_print(int level, char *message, ...)
{
	va_list ap;
	static int newline = 1;

	if (level > debug_level) {
		return;
	}

	va_start(ap, message);
	if (level == 0) {
		if (logflag) {
			(void) vsyslog(LOG_ERR, message, ap);
		} else {
			(void) vfprintf(stderr, message, ap);
		}

	} else {
		if (logflag) {
			(void) syslog(LOG_DEBUG, "%s[%ld]: ",
			    prog, getpid());
			(void) vsyslog(LOG_DEBUG, message, ap);
		} else {
			if (newline) {
				(void) fprintf(stdout, "%s[%ld]: ",
				    prog, getpid());
				(void) vfprintf(stdout, message, ap);
			} else {
				(void) vfprintf(stdout, message, ap);
			}
		}
	}
	if (message[strlen(message)-1] == '\n') {
		newline = 1;
	} else {
		newline = 0;
	}
	va_end(ap);
}


char *
int2string(intmap_t *map, int value)
{
	const char	*name = (const char *)NULL;
	char		charstr[100];

	for (; map->im_name != (const char *)NULL; map++) {
		if (map->im_int == value) {
			name = map->im_name;
			break;
		}
	}
	if (name == (const char *)NULL) {
		/* No match.  Convert the string to an int. */
		(void) sprintf(charstr, "%d", value);
	} else {
		(void) snprintf(charstr, sizeof (charstr), "%d %s",
		    value, name);
	}
	return (strdup(charstr));
}

void
probe_all_devs(boolean_e startup, md_error_t *statusp, boolean_e verbose)
{
	set_t		max_sets, set_idx;

	probe_started = True;
	(void) set_snarf(statusp);

	if ((max_sets = get_max_sets(statusp)) == 0) {
		mde_perror(statusp, gettext(
		    "Can't find max number of sets\n"));
		monitord_exit(1);
	}

	/*
	 * We delete the FF_Q to avoid recurse errors. Yes we will lose
	 * some but its the corner case.
	 */

	if (startup == False &&
	    (meta_notify_deleteq(MD_FF_Q, statusp) != 0)) {
		mde_perror(statusp, gettext(
		    "delete queue failed\n"));
		monitord_exit(1);
	}

	for (set_idx = 0; set_idx < max_sets; set_idx++) {
		if ((sp = metasetnosetname(set_idx, statusp)) == NULL) {
			if (mdiserror(statusp, MDE_NO_SET) == 0) {
				/*
				 * done break the loop
				 */
				break;
			} else {
				mdclrerror(statusp);
				continue;
			}
		}

		/* if we dont have ownership or cannot lock it continue. */
		if ((meta_check_ownership(sp, statusp) == NULL) &&
		    meta_lock(sp, TRUE, statusp))
			continue;

		/* Skip if a MN set */
		if (meta_is_mn_set(sp, statusp)) {
			(void) meta_unlock(sp, statusp);
			continue;
		}

		probe_mirror_devs(verbose);
		probe_raid_devs(verbose);
		probe_trans_devs(verbose);
		probe_hotspare_devs(verbose);
		(void) meta_unlock(sp, statusp);
	}
	if (meta_notify_createq(MD_FF_Q, 0, statusp)) {
		mde_perror(statusp, gettext(
		    "create queue failed"));
		monitord_exit(1);
	}
	probe_started = False;
	/*
	 * need to do it here only at startup.
	 * The daemon will restart the alarm.
	 */

	if (startup == True)
		(void) setitimer(ITIMER_REAL, &itimer, NULL);
}

evid_t
wait_for_event(md_error_t *statusp)
{
	md_ev_t		event;


	event.setno = EV_ALLSETS;
	event.obj = EV_ALLOBJS;

	do {
		if (meta_notify_getev(MD_FF_Q, EVFLG_WAIT, &event,
		    statusp) < 0) {
			monitord_print(8,
			    "meta_notify_getev: errno 0x%x\n", -errno);
			monitord_exit(-errno);
		}
	} while ((event.ev != EV_IOERR && event.ev != EV_ERRED &&
	    event.ev != EV_LASTERRED));
	return (event.ev);
}

int
main(int argc, char **argv)
{
	boolean_e	startup = True;
	boolean_e	verbose = False;
	int		i;
	char		c;
	md_error_t	status = mdnullerror;
	struct sigaction act;
	sigset_t	mask;
	unsigned long	timerval = 0;

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

	if (sdssc_bind_library() == SDSSC_ERROR) {
		(void) printf(gettext(
		    "%s: Interface error with libsds_sc.so\n"), argv[0]);
		exit(1);
	}

	if (md_init(argc, argv, 0, 1, &status) != 0 ||
	    meta_check_root(&status) != 0) {
		mde_perror(&status, "");
		monitord_exit(1);
	}

	(void) sigfillset(&mask);
	(void) thr_sigsetmask(SIG_BLOCK, &mask, NULL);

	if (argc > 7) {
		usage();
	}

	if ((prog = strrchr(argv[0], '/')) == NULL) {
		prog = argv[0];
	} else {
		prog++;
	}

	/*
	 * Reset optind/opterr so that the command line arguments can be
	 * parsed. This is in case anything has already called getopt,
	 * for example sdssc_cmd_proxy which is not currently used but
	 * may be in the future.
	 */
	optind = 1;
	opterr = 1;
	while ((c = getopt(argc, argv, "ivd:t:")) != EOF) {
		switch (c) {
		case 'v':
			verbose = True;
			break;
		case 'i':
			issue_ioctl = True;
			break;
		case 'd':
			debug_level = atoi(optarg);
			break;
		case 't':
			timerval = atol(optarg);
			break;
		default:
			usage();
			exit(0);
		}
	}

	if (timerval == 0) {
		monitord_print(8, gettext(
		    "operating in interrupt mode\n"));
	} else {
		itimer.it_value.tv_sec = timerval;
		itimer.it_interval.tv_sec = timerval;
		monitord_print(8, gettext(
		    "set value and interval %lu sec  mode\n"), timerval);
	}
	/*
	 * set up our signal handler for SIGALRM. The
	 * rest are setup by md_init.
	 */

	act.sa_handler = catch_sig;
	(void) sigemptyset(&act.sa_mask);
	act.sa_flags = SA_RESTART;
	(void) sigaction(SIGALRM, &act, NULL);
	(void) sigaction(SIGHUP, &act, NULL);

	(void) sigemptyset(&mask);
	(void) sigaddset(&mask, SIGALRM);
	(void) sigaddset(&mask, SIGHUP);
	(void) thr_sigsetmask(SIG_UNBLOCK, &mask, NULL);

	/* demonize ourselves */
	if (debug_level < DEBUG_LEVEL_FORK) {
		pid_t pid;

		if ((pid = check_daemon_lock()) != 0) {
			monitord_print(0, gettext(
			    "mdmonitord daemon pid %ld already running\n"),
			    pid);
			exit(-1);
		}

		if (fork()) {
			exit(0);
		}

		/* only one daemon can run at a time */
		if ((pid = enter_daemon_lock()) != 0) {
			monitord_print(0, gettext(
			    "mdmonitord daemon pid %ld already running\n"),
			    pid);
			exit(-1);
		}

		(void) chdir("/");

		(void) setsid();
		if (debug_level <= 1) {
			for (i = 0; i < 3; i++) {
				(void) close(i);
			}
			(void) open("/dev/null", 0);
			(void) dup2(0, 1);
			(void) dup2(0, 2);
			logflag = 1;
		}
	}

	openlog("mdmonitord", LOG_PID, LOG_DAEMON);

	monitord_print(8, gettext(
	    "mdmonitord started, debug level = %d\n"), debug_level);


	/* loop forever waiting for events */
	do {
		metaflushnames(1);
		probe_all_devs(startup, &status, verbose);
		startup = False; /* since we have gone through once */
	} while (wait_for_event(&status));
	return (0);
}
