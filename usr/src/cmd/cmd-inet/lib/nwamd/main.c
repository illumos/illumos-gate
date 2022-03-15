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
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include <errno.h>
#include <fcntl.h>
#include <libdllink.h>
#include <libintl.h>
#include <libnwam.h>
#include <locale.h>
#include <priv.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <libnwam.h>
#include "conditions.h"
#include "events.h"
#include "llp.h"
#include "ncp.h"
#include "objects.h"
#include "util.h"

/*
 * nwamd - NetWork Auto-Magic Daemon
 */

boolean_t fg = B_FALSE;
dladm_handle_t dld_handle = NULL;
ipadm_handle_t ipadm_handle = NULL;
boolean_t shutting_down = B_FALSE;

sigset_t original_sigmask;
static sigset_t sigwaitset;

static void nwamd_refresh(void);
static void graceful_shutdown(void);

/*
 * nwamd
 *
 * This is the Network Auto-Magic daemon.  For further high level information
 * see the Network Auto-Magic project and the Approachability communities
 * on opensolaris.org, nwamd(8), and the README in the source directory.
 *
 * The general structure of the code is as a set of event source threads
 * which feed events into the event handling thread. Some of these events
 * are internal-only (e.g UPGRADE), but some also involve propogation
 * to external listeners (who register via a door call into the daemon).
 *
 * signal management
 * Due to being threaded, a simple set of signal handlers would not work
 * very well for nwamd.  Instead nwamd blocks signals in all but the
 * signal handling thread at startup.
 *
 */

/*
 * In this file there are several utility functions which might otherwise
 * belong in util.c, but since they are only called from main(), they can
 * live here as static functions:
 * - nlog set-up
 * - daemonizing
 * - looking up smf(7) properties
 * - signal handling
 * - managing privileges(7)
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
	if ((pid = fork()) == (pid_t)-1)
		pfail("fork 1 failed");
	if (pid != 0) {
		(void) wait(NULL);
		nlog(LOG_DEBUG, "child %ld exited, daemonizing", pid);
		_exit(0);
	}
	if (setsid() == (pid_t)-1)
		pfail("setsid");
	if ((pid = fork()) == (pid_t)-1)
		pfail("fork 2 failed");
	if (pid != 0) {
		_exit(0);
	}
	(void) chdir("/");
	(void) umask(022);
}

/* ARGSUSED */
static void *
sighandler(void *arg)
{
	int sig;

	while (!shutting_down) {
		sig = sigwait(&sigwaitset);
		nlog(LOG_DEBUG, "signal %s caught", strsignal(sig));

		switch (sig) {
		case SIGTHAW:
		case SIGHUP:
			/*
			 * Resumed from suspend or refresh.  Clear up all
			 * objects so their states start from scratch;
			 * then refresh().
			 */
			nwamd_fini_enms();
			nwamd_fini_ncus();
			nwamd_fini_locs();
			nwamd_refresh();
			break;
		case SIGUSR1:
			/*
			 * Undocumented "log ncu list" signal.
			 */
			nwamd_log_ncus();
			break;
		case SIGTERM:
			nlog(LOG_DEBUG, "%s received, shutting down",
			    strsignal(sig));
			graceful_shutdown();
			break;
		default:
			nlog(LOG_DEBUG, "unexpected signal %s received, "
			    "ignoring", strsignal(sig));
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

	(void) pthread_attr_init(&attr);
	(void) pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
	if (err = pthread_create(&sighand, &attr, sighandler, NULL)) {
		nlog(LOG_ERR, "pthread_create system: %s", strerror(err));
		exit(EXIT_FAILURE);
	} else {
		nlog(LOG_DEBUG, "signal handler thread: %d", sighand);
	}
	(void) pthread_attr_destroy(&attr);
}

/*
 * Construct the set of signals that we explicitly want to deal with.
 * We block these while we're still single-threaded; this block will
 * be inherited by all the threads we create.  When we are ready to
 * start handling signals, we will start the signal handling thread,
 * which will sigwait() this same set of signals, and will thus receive
 * and handle any that are sent to the process.
 */
static void
block_signals(void)
{
	(void) sigemptyset(&sigwaitset);
	(void) sigaddset(&sigwaitset, SIGHUP);
	(void) sigaddset(&sigwaitset, SIGUSR1);
	(void) sigaddset(&sigwaitset, SIGUSR2);
	(void) sigaddset(&sigwaitset, SIGTERM);
	(void) sigaddset(&sigwaitset, SIGTHAW);
	(void) pthread_sigmask(SIG_BLOCK, &sigwaitset, &original_sigmask);
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
	char *active_ncp_tmp;
	char *scan_level_tmp;

	(void) nwamd_lookup_boolean_property(OUR_FMRI, OUR_PG,
	    OUR_DEBUG_PROP_NAME, &debug);
	(void) nwamd_lookup_boolean_property(OUR_FMRI, OUR_PG,
	    OUR_AUTOCONF_PROP_NAME, &wireless_autoconf);
	(void) nwamd_lookup_boolean_property(OUR_FMRI, OUR_PG,
	    OUR_STRICT_BSSID_PROP_NAME, &wireless_strict_bssid);

	(void) pthread_mutex_lock(&active_ncp_mutex);
	if ((active_ncp_tmp = malloc(NWAM_MAX_NAME_LEN)) == NULL ||
	    nwamd_lookup_string_property(OUR_FMRI, OUR_PG,
	    OUR_ACTIVE_NCP_PROP_NAME, active_ncp_tmp, NWAM_MAX_NAME_LEN) != 0) {
		(void) strlcpy(active_ncp, NWAM_NCP_NAME_AUTOMATIC,
		    NWAM_MAX_NAME_LEN);
	} else {
		(void) strlcpy(active_ncp, active_ncp_tmp, NWAM_MAX_NAME_LEN);
	}
	(void) pthread_mutex_unlock(&active_ncp_mutex);
	free(active_ncp_tmp);

	if (nwamd_lookup_count_property(OUR_FMRI, OUR_PG,
	    OUR_CONDITION_CHECK_INTERVAL_PROP_NAME,
	    &condition_check_interval) != 0)
		condition_check_interval = CONDITION_CHECK_INTERVAL_DEFAULT;

	if ((scan_level_tmp = malloc(NWAM_MAX_NAME_LEN)) == NULL ||
	    nwamd_lookup_string_property(OUR_FMRI, OUR_PG,
	    OUR_WIRELESS_SCAN_LEVEL_PROP_NAME, scan_level_tmp,
	    NWAM_MAX_NAME_LEN) != 0) {
		wireless_scan_level = WIRELESS_SCAN_LEVEL_DEFAULT;
	} else {
		if (dladm_wlan_str2strength(scan_level_tmp,
		    &wireless_scan_level) != DLADM_STATUS_OK)
			wireless_scan_level = DLADM_WLAN_STRENGTH_VERY_WEAK;
	}
	free(scan_level_tmp);

	if (nwamd_lookup_count_property(OUR_FMRI, OUR_PG,
	    OUR_WIRELESS_SCAN_INTERVAL_PROP_NAME, &wireless_scan_interval) != 0)
		wireless_scan_interval = WIRELESS_SCAN_INTERVAL_DEFAULT;

	if (nwamd_lookup_count_property(OUR_FMRI, OUR_PG,
	    OUR_NCU_WAIT_TIME_PROP_NAME, &ncu_wait_time) != 0)
		ncu_wait_time = NCU_WAIT_TIME_DEFAULT;

	nlog(LOG_DEBUG, "Read daemon configuration properties.");
}

/*
 * Re-read the SMF properties.
 * Reset ncu priority group (since the NCUs will have to walk
 *   through their state machines again) and schedule a check
 * Re-read objects from libnwam.
 * Also, run condition checking for locations and ENMs.
 */
static void
nwamd_refresh(void)
{
	lookup_daemon_properties();

	(void) pthread_mutex_lock(&active_ncp_mutex);
	current_ncu_priority_group = INVALID_PRIORITY_GROUP;
	(void) pthread_mutex_unlock(&active_ncp_mutex);

	nwamd_init_ncus();
	nwamd_init_enms();
	nwamd_init_locs();

	nwamd_create_ncu_check_event(0);
	nwamd_create_triggered_condition_check_event(0);
}

static void
graceful_shutdown(void)
{
	nwamd_event_t event;

	shutting_down = B_TRUE;
	nwamd_event_sources_fini();
	nwamd_door_fini();
	nwamd_fini_enms();
	nwamd_fini_ncus();
	nwamd_fini_locs();

	event = nwamd_event_init_shutdown();
	if (event == NULL)
		pfail("nwamd could not create shutdown event, exiting");
	nwamd_event_enqueue(event);
}

int
main(int argc, char *argv[])
{
	int c;
	uint64_t version;
	nwamd_event_t event;
	dladm_status_t drc;
	ipadm_status_t irc;
	uid_t uid = getuid();

	/*
	 * Block the signals we care about (and which might cause us to
	 * exit based on default disposition) until we're ready to start
	 * handling them properly...see init_signalhandling() below.
	 */
	block_signals();

	if (uid != UID_NETADM && uid != 0) {
		/*
		 * This shouldn't happen normally.  On upgrade the service might
		 * need reloading.
		 */
		pfail("nwamd should run as uid %d, not uid %d\n", UID_NETADM,
		    uid);
	}

	(void) setlocale(LC_ALL, "");
	(void) textdomain(TEXT_DOMAIN);

	start_logging();
	nlog(LOG_INFO, "nwamd pid %d started", getpid());

	while ((c = getopt(argc, argv, "fs:")) != -1) {
		switch (c) {
			case 'f':
				fg = B_TRUE;
				break;
			default:
				nlog(LOG_ERR, "unrecognized option %c",
				    optopt);
				break;
		}
	}

	lookup_daemon_properties();

	if (!fg)
		daemonize();

	/*
	 * The dladm handle *must* be opened before privileges are dropped.
	 * The device privilege requirements, which are stored in
	 * /etc/security/device_policy, may not be loaded yet, as that's
	 * done by svc:/system/filesystem/root.  If they are not loaded,
	 * then one must have *all* privs in order to open /dev/dld, which
	 * is one of the steps performed in dladm_open().
	 */
	drc = dladm_open(&dld_handle);
	if (drc != DLADM_STATUS_OK) {
		char status_str[DLADM_STRSIZE];
		pfail("failed to open dladm handle: %s",
		    dladm_status2str(drc, status_str));
	}

	irc = ipadm_open(&ipadm_handle, 0);
	if (irc != IPADM_SUCCESS)
		pfail("failed to open ipadm handle: %s", ipadm_status2str(irc));

	/*
	 * Create the event queue before starting event sources, including
	 * signal handling, so we are ready to handle incoming events.  Also
	 * start before attempting to upgrade, in case there's a problem
	 * upgrading and we need to retry (in which case we schedule an event
	 * to do so).
	 */
	nwamd_event_queue_init();

	/*
	 * Handle upgrade of legacy config.  Absence of version property
	 * (which did not exist in phase 0 or 0.5) is the indication that
	 * we need to upgrade to phase 1 (version 1).
	 */
	if (nwamd_lookup_count_property(OUR_FMRI, OUR_PG, OUR_VERSION_PROP_NAME,
	    &version) != 0)
		nwamd_handle_upgrade(NULL);

	/*
	 * Initialize lists handling internal representations of objects.
	 */
	nwamd_object_lists_init();

	init_signalhandling();

	/* Enqueue init event */
	event = nwamd_event_init_init();
	if (event == NULL)
		pfail("nwamd could not create init event, exiting");
	nwamd_event_enqueue(event);

	/*
	 * Collect initial user configuration.
	 */

	/*
	 * Walk the physical interfaces and update the Automatic NCP to
	 * contain the IP and link NCUs for the interfaces that exist in
	 * the system.
	 */
	nwamd_walk_physical_configuration();

	/*
	 * We should initialize the door at the point that we can respond to
	 * user requests about the system but before we start actually process
	 * state changes or effecting the system.
	 */
	nwamd_door_init();

	/*
	 * Initialize data objects.
	 *
	 * Enabling an NCP involves refreshing nwam, which initializes the
	 * objects (ncu, enm, loc, known wlan).  Thus, no need to
	 * explicitly initialize these objects here.  The refresh also
	 * enqueues and NCU activation checking event.  Location and ENM
	 * condition checking are triggered by changes in NCU states.
	 */
	(void) pthread_mutex_lock(&active_ncp_mutex);
	if (nwamd_ncp_action(active_ncp, NWAM_ACTION_ENABLE) != 0)
		pfail("Initial enable failed for active NCP %s", active_ncp);
	(void) pthread_mutex_unlock(&active_ncp_mutex);

	/*
	 * Enqueue an event to start periodic checking of activation conditions.
	 */
	nwamd_create_timed_condition_check_event();

	/*
	 * These two routines safely minimize our privilege set.  They
	 * use reference counting to be safe in a threaded program.  It is
	 * gross that we escalate/deescalate to initialize this functionality
	 * but a real fix is to add functionality to do fine grained privs
	 * (and if necessary set uid to 0) in this threaded daemon.
	 */
	nwamd_escalate();
	nwamd_deescalate();

	/*
	 * Start the various agents (hooks on fds, threads) which collect events
	 */
	nwamd_event_sources_init();

	/*
	 * nwamd_event_handler() only returns on shutdown.
	 */
	nwamd_event_handler();

	ipadm_close(ipadm_handle);
	dladm_close(dld_handle);

	return (EXIT_SUCCESS);
}
