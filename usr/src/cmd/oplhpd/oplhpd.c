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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/param.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/sysevent/eventdefs.h>
#include <sys/sysevent/dr.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <syslog.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
#include <config_admin.h>
#include <libsysevent.h>


/* Signal handler type */
typedef void (SigHandler)(int);
/* oplhpd process id file descriptor */
static int pid_fd;

/* Program Name */
char	*oplhpd_prog_name = "";

/* Macros */
#define	OPLHPD_DEV_DIR "/devices"	/* device base dir */
#define	OPLHPD_PID_FILE "/var/run/oplhpd.pid" /* lock file path */
#define	OPLHPD_PROG_NAME oplhpd_prog_name

/* Event handler to get information */
static sysevent_handle_t *oplhpd_hdl;


/*
 * Function Prototypes
 */
void quit_daemon(int signo);
SigHandler *set_sig_handler(int sig, SigHandler *handler);
void init_daemon(void);
void oplhpd_init(void);
void oplhpd_fini(void);
static void oplhpd_event(sysevent_t *ev);

extern void notify_scf_of_hotplug(sysevent_t *ev);


/*
 * Terminate and Quit Daemon Process.
 * signo = 0 ... normal   quit
 *       > 0 ... signaled quit
 *       < 0 ... failure  quit
 */
void
quit_daemon(int signo)
{
	int status = 0;
	id_t pgid;

	syslog(LOG_DEBUG, "*** quit daemon [pid:%d, signal#:%d].\n",
			getpid(), signo);

	(void) set_sig_handler(SIGTERM, SIG_IGN);
	pgid = getpgrp();
	(void) kill(-pgid, SIGTERM);

	(void) close(pid_fd);
	(void) unlink(OPLHPD_PID_FILE); /* clean up lock file */

	if (signo < 0) {
		status = signo;
	}
	_exit(status);
}

/*
 * Setting the signal handler utility
 */
SigHandler *
set_sig_handler(int sig, SigHandler *handler)
{
	struct sigaction act, oact;

	act.sa_handler = handler;
	act.sa_flags = 0;
	if (sig == SIGCHLD && handler == SIG_IGN) {
		act.sa_flags |= SA_NOCLDWAIT;
	}
	(void) sigemptyset(&act.sa_mask);
	(void) sigemptyset(&oact.sa_mask);
	if (sigaction(sig, &act, &oact) < 0) {
		return (SIG_ERR);
	}

	return (oact.sa_handler);
}

/*
 * Setup oplhpd daemon
 */
void
init_daemon()
{
	int	i;
	int	ret;
	int	fd;
	pid_t	pid;
	char	pid_str[32];

	if (geteuid() != 0) {
		syslog(LOG_ERR, "must be root to execute %s\n",
				OPLHPD_PROG_NAME);
		exit(1);
	}

	/*
	 * Daemonize
	 */
	if ((pid = fork()) < 0) {
		perror("fork failed");
		exit(1);
	}
	if (pid > 0) {
	/* Parent, exit. */
		exit(0);
	}
	(void) setsid();
	(void) chdir("/");
	(void) umask(0);
	(void) closefrom(0);
	(void) open("/dev/null", O_RDONLY);
	(void) open("/dev/null", O_WRONLY);
	(void) dup(1);

	(void) openlog(OPLHPD_PROG_NAME, LOG_PID, LOG_DAEMON);

	/*
	 * Create the lock file for singletonize
	 */
	if ((pid_fd = open(OPLHPD_PID_FILE, O_RDWR | O_CREAT, 0644)) < 0) {
		syslog(LOG_ERR, "could not create pid file: %s",
		strerror(errno));
		exit(1);
	}
	if (lockf(pid_fd, F_TLOCK, 0L) < 0) {
		if (errno == EACCES || errno == EAGAIN) {
			syslog(LOG_ERR, "another oplhpd is already running");
		} else {
			syslog(LOG_ERR, "could not lock pid file");
		}
		exit(1);
		}

	(void) ftruncate(pid_fd, 0);
	i = sprintf(pid_str, "%d\n", getpid());
	while ((ret = write(pid_fd, pid_str, i)) != i) {
		if (errno == EINTR) {
			continue;
		}
		if (ret < 0) {
			syslog(LOG_ERR, "pid file write fail: %s",
			strerror(errno));
			exit(1);
		}
	}

	/*
	 * Set signal handlers
	 */
	(void) set_sig_handler(SIGTERM, (SigHandler *)quit_daemon);
	(void) set_sig_handler(SIGQUIT, (SigHandler *)quit_daemon);
	(void) set_sig_handler(SIGINT,  (SigHandler *)quit_daemon);
	(void) set_sig_handler(SIGCHLD, SIG_IGN);
}

static void
oplhpd_event(sysevent_t *ev)
{
	/*
	 * Inform the SCF of the change in the state of the pci hot plug
	 * cassette.
	 */
	notify_scf_of_hotplug(ev);

}

/*
 * Initialization for hotplug event.
 * - Bind event handler.
 * - Subscribe the handler to the hotplug event.
 */
void
oplhpd_init()
{
	const char *subclass = ESC_DR_AP_STATE_CHANGE;

	syslog(LOG_DEBUG, "oplhpd_init");

	oplhpd_hdl = sysevent_bind_handle(oplhpd_event);
	if (oplhpd_hdl == NULL) {
		syslog(LOG_ERR, "event handler bind fail");
		quit_daemon(-1);
	}

	if (sysevent_subscribe_event(oplhpd_hdl, EC_DR, &subclass, 1) != 0) {
		syslog(LOG_ERR, "event handler subscribe fail");
		sysevent_unbind_handle(oplhpd_hdl);
		quit_daemon(-1);
	}

	for (;;) {
		(void) pause();
	}
}

void
oplhpd_fini()
{
	if (oplhpd_hdl != NULL) {
		sysevent_unsubscribe_event(oplhpd_hdl, EC_DR);
		sysevent_unbind_handle(oplhpd_hdl);
	}
}

int
main(int argc, char *argv[])
{
	int opt;

	/* Get Program Name */
	if ((oplhpd_prog_name = strrchr(argv[0], '/')) == NULL) {
		oplhpd_prog_name = argv[0];
	} else {
		oplhpd_prog_name++;
	}

	/* Check the daemon running lock and Initialize the signal */
	init_daemon();

	/* Subscribe to the hotplug event */
	oplhpd_init();

	/* Unsubscribe the hotplug event */
	oplhpd_fini();

	return (0);
}
