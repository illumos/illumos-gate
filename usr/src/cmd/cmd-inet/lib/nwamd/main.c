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
 * nwamd - NetWork Auto-Magic Daemon
 */

#include <fcntl.h>
#include <priv.h>
#include <pthread.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <syslog.h>
#include <unistd.h>
#include <locale.h>
#include <libintl.h>
#include <errno.h>

#include "defines.h"
#include "structures.h"
#include "functions.h"
#include "variables.h"

#define	TIMESPECGT(x, y)	((x.tv_sec > y.tv_sec) || \
	    ((x.tv_sec == y.tv_sec) && (x.tv_nsec > y.tv_nsec)))

const char *OUR_FMRI = "svc:/network/physical:nwam";
const char *OUR_PG = "nwamd";

boolean_t fg = B_FALSE;
boolean_t shutting_down;
sigset_t original_sigmask;
char zonename[ZONENAME_MAX];
pthread_mutex_t machine_lock = PTHREAD_MUTEX_INITIALIZER;

/*
 * nwamd
 *
 * This is the Network Auto-Magic daemon.  For further high level information
 * see the Network Auto-Magic project and the Approachability communities
 * on opensolaris.org, and nwamd(1M).
 *
 * The general structure of the code is as a set of threads collecting
 * system events which are fed into a state machine which alters system
 * state based on configuration.
 *
 * signal management
 * Due to being threaded, a simple set of signal handlers would not work
 * very well for nwamd.  Instead nwamd blocks signals at startup and
 * then starts a thread which sits in sigwait(2) waiting for signals.
 * When a signal is received the signal handling thread dispatches it.
 * It handles:
 * - shutting down, done by creating an event which is passed through the
 *   system allowing the various subsystems to do any necessary cleanup.
 * - SIGALRM for timers.
 * - SIGHUP for instance refresh, which tells us to look up various
 *   properties from SMF(5).
 *
 * subprocess management
 * nwamd starts several different subprocesses to manage the system.  Some
 * of those start other processes (e.g. `ifconfig <if> dhcp` ends up starting
 * dhcpagent if necessary).  Due to the way we manage signals if we started
 * those up without doing anything special their signal mask would mostly
 * block signals.  So we restore the signal mask when we start subprocesses.
 * This is especially important with respect to DHCP as later when we exit
 * we need to kill the dhcpagent process which we started; for details, see
 * the block comment in state_machine.c in its cleanup() function.
 */

/*
 * In this file there are several utility functions which might otherwise
 * belong in util.c, but since they are only called from main(), they can
 * live here as static functions:
 * - syslog set-up
 * - daemonizing
 * - looking up SMF(5) properties
 * - signal handling
 * - managing privileges(5)
 */

static void
start_logging(void)
{
	openlog("nwamd", LOG_PID | LOG_NDELAY, LOG_DAEMON);
}

static void
daemonize(void)
{
	pid_t pid;

	/*
	 * A little bit of magic here.  By the first fork+setsid, we
	 * disconnect from our current controlling terminal and become
	 * a session group leader.  By forking again without calling
	 * setsid again, we make certain that we are not the session
	 * group leader and can never reacquire a controlling terminal.
	 */
	if ((pid = fork()) == (pid_t)-1) {
		syslog(LOG_ERR, "fork 1 failed");
		exit(EXIT_FAILURE);
	}
	if (pid != 0) {
		(void) wait(NULL);
		dprintf("child %ld exited, daemonizing", pid);
		_exit(0);
	}
	if (setsid() == (pid_t)-1) {
		syslog(LOG_ERR, "setsid");
		exit(EXIT_FAILURE);
	}
	if ((pid = fork()) == (pid_t)-1) {
		syslog(LOG_ERR, "fork 2 failed");
		exit(EXIT_FAILURE);
	}
	if (pid != 0) {
		_exit(0);
	}
	(void) chdir("/");
	(void) umask(022);
}

/*
 * Look up nwamd property values and set daemon variables appropriately.
 * This function will be called on startup and via the signal handling
 * thread on receiving a HUP (which occurs when the nwam service is
 * refreshed).
 */
static void
lookup_daemon_properties(void)
{
	boolean_t debug_set;
	uint64_t scan_interval;
	uint64_t idle_time;

	if (lookup_boolean_property(OUR_PG, "debug", &debug_set) == 0)
		debug = debug_set;
	if (lookup_count_property(OUR_PG, "scan_interval", &scan_interval) == 0)
		wlan_scan_interval = scan_interval;
	if (lookup_count_property(OUR_PG, "idle_time", &idle_time) == 0)
		door_idle_time = idle_time;
	dprintf("Read daemon configuration properties.");
}

/* ARGSUSED */
static void *
sighandler(void *arg)
{
	sigset_t sigset;
	int sig;
	uint32_t now;

	(void) sigfillset(&sigset);

	while (!shutting_down) {
		sig = sigwait(&sigset);
		dprintf("signal %d caught", sig);
		switch (sig) {
		case SIGALRM:
			/*
			 * We may have multiple interfaces with
			 * scheduled timers; walk the list and
			 * create a timer event for each one.
			 */
			timer_expire = TIMER_INFINITY;
			now = NSEC_TO_SEC(gethrtime());
			check_interface_timers(now);
			check_door_life(now);
			break;
		case SIGHUP:
			/*
			 * Refresh action - reread configuration properties.
			 */
			lookup_daemon_properties();
			break;
		case SIGINT:
			/*
			 * Undocumented "print debug status" signal.
			 */
			print_llp_status();
			print_interface_status();
			print_wireless_status();
			break;
		default:
			syslog(LOG_NOTICE, "%s received, shutting down",
			    strsignal(sig));
			shutting_down = B_TRUE;
			if (!np_queue_add_event(EV_SHUTDOWN, NULL)) {
				dprintf("could not allocate shutdown event");
				cleanup();
				exit(EXIT_FAILURE);
			}
			break;
		}
	}
	return (NULL);
}

static void
init_signalhandling(void)
{
	pthread_attr_t attr;
	pthread_t sighand;
	int err;
	sigset_t new;

	(void) sigfillset(&new);
	(void) pthread_sigmask(SIG_BLOCK, &new, &original_sigmask);
	(void) pthread_attr_init(&attr);
	(void) pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
	if (err = pthread_create(&sighand, &attr, sighandler, NULL)) {
		syslog(LOG_ERR, "pthread_create system: %s", strerror(err));
		exit(EXIT_FAILURE);
	} else {
		dprintf("signal handler thread: %d", sighand);
	}
	(void) pthread_attr_destroy(&attr);
}

static void
change_user_set_privs(void)
{
	priv_set_t *priv_set;

	priv_set = priv_allocset();
	if (getppriv(PRIV_PERMITTED, priv_set) == -1) {
		dprintf("getppriv %s", strerror(errno));
	} else {
		char *p;

		p = priv_set_to_str(priv_set, ',', 0);
		dprintf("started with privs %s", p != NULL ? p : "Unknown");
		free(p);
	}
	priv_freeset(priv_set);

	/* always start with the basic set */
	priv_set = priv_str_to_set("basic", ",", NULL);
	if (priv_set == NULL) {
		syslog(LOG_ERR, "converting basic privilege set: %m");
		exit(EXIT_FAILURE);
	}
	(void) priv_addset(priv_set, PRIV_FILE_CHOWN_SELF);
	(void) priv_addset(priv_set, PRIV_FILE_DAC_READ);
	(void) priv_addset(priv_set, PRIV_FILE_DAC_WRITE);
	(void) priv_addset(priv_set, PRIV_NET_PRIVADDR);
	(void) priv_addset(priv_set, PRIV_NET_RAWACCESS);
	(void) priv_addset(priv_set, PRIV_PROC_AUDIT);
	(void) priv_addset(priv_set, PRIV_PROC_OWNER);
	(void) priv_addset(priv_set, PRIV_PROC_SETID);
	(void) priv_addset(priv_set, PRIV_SYS_CONFIG);
	(void) priv_addset(priv_set, PRIV_SYS_IP_CONFIG);
	(void) priv_addset(priv_set, PRIV_SYS_IPC_CONFIG);
	(void) priv_addset(priv_set, PRIV_SYS_NET_CONFIG);
	(void) priv_addset(priv_set, PRIV_SYS_RES_CONFIG);
	(void) priv_addset(priv_set, PRIV_SYS_RESOURCE);

	if (setppriv(PRIV_SET, PRIV_INHERITABLE, priv_set) == -1) {
		syslog(LOG_ERR, "setppriv inheritable: %m");
		priv_freeset(priv_set);
		exit(EXIT_FAILURE);
	}

	if (setppriv(PRIV_SET, PRIV_PERMITTED, priv_set) == -1) {
		syslog(LOG_ERR, "setppriv permitted: %m");
		priv_freeset(priv_set);
		exit(EXIT_FAILURE);
	}

	if (setppriv(PRIV_SET, PRIV_EFFECTIVE, priv_set) == -1) {
		syslog(LOG_ERR, "setppriv effective: %m");
		priv_freeset(priv_set);
		exit(EXIT_FAILURE);
	}

	priv_freeset(priv_set);
}

static void
init_machine_mutex(void)
{
	pthread_mutexattr_t attrs;

	(void) pthread_mutexattr_init(&attrs);
	(void) pthread_mutexattr_settype(&attrs, PTHREAD_MUTEX_ERRORCHECK);
	if (pthread_mutex_init(&machine_lock, &attrs) != 0) {
		syslog(LOG_ERR, "unable to set up machine lock");
		exit(EXIT_FAILURE);
	}
	(void) pthread_mutexattr_destroy(&attrs);
}

int
main(int argc, char *argv[])
{
	int c;
	int scan_lev;
	struct np_event *e;
	enum np_event_type etype;

	(void) setlocale(LC_ALL, "");
	(void) textdomain(TEXT_DOMAIN);

	shutting_down = B_FALSE;
	start_logging();
	syslog(LOG_INFO, "nwamd pid %d started", getpid());

	while ((c = getopt(argc, argv, "fs:")) != -1) {
		switch (c) {
			case 'f':
				fg = B_TRUE;
				break;
			case 's':
				scan_lev = atoi(optarg);
				if (scan_lev >= DLADM_WLAN_STRENGTH_VERY_WEAK &&
				    scan_lev <= DLADM_WLAN_STRENGTH_EXCELLENT) {
					wireless_scan_level = scan_lev;
				} else {
					syslog(LOG_ERR, "invalid signal "
					    "strength: %s", optarg);
				}
				break;
			default:
				syslog(LOG_ERR, "unrecognized option %c",
				    optopt);
				break;
		}
	}

	lookup_daemon_properties();

	change_user_set_privs();

	if (!fg)
		daemonize();

	initialize_llp();

	init_signalhandling();

	initialize_wireless();

	lookup_zonename(zonename, sizeof (zonename));

	init_machine_mutex();

	initialize_interfaces();

	llp_parse_config();

	initialize_door();

	(void) start_event_collection();

	while ((e = np_queue_get_event()) != NULL) {

		etype = e->npe_type;
		syslog(LOG_INFO, "got event type %s", npe_type_str(etype));
		if (etype == EV_SHUTDOWN)
			terminate_door();
		if (pthread_mutex_lock(&machine_lock) != 0) {
			syslog(LOG_ERR, "mutex lock");
			exit(EXIT_FAILURE);
		}
		state_machine(e);
		(void) pthread_mutex_unlock(&machine_lock);
		free_event(e);
		if (etype == EV_SHUTDOWN)
			break;
	}
	syslog(LOG_DEBUG, "terminating routing and scanning threads");
	(void) pthread_cancel(routing);
	(void) pthread_cancel(scan);
	(void) pthread_join(routing, NULL);
	(void) pthread_join(scan, NULL);
	syslog(LOG_INFO, "nwamd shutting down");
	return (EXIT_SUCCESS);
}
