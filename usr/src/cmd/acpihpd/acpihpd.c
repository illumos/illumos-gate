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
 * Copyright (c) 2010, Intel Corporation.
 * All rights reserved.
 */

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
#include <strings.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
#include <config_admin.h>
#include <libscf.h>
#include <libsysevent.h>
#include <stdarg.h>

/* Signal handler type */
typedef void (sig_handler_t)(int);

#define	ACPIHPD_PID_FILE "/var/run/acpihpd.pid" /* lock file path */

/* Program Name */
char *g_prog_name;
int g_debuglevel = 0;

static int s_pid_fd;
static sysevent_handle_t *s_acpihpd_hdl;

static int daemon_init(void);
static void daemon_quit(int);
static int set_sig_handler(int, sig_handler_t *);
static int acpihpd_init(void);
static void acpihpd_fini(void);
static void acpihpd_event(sysevent_t *);
extern void notify_hotplug(sysevent_t *ev);
void debug_print(int, const char *, ...);

int
main(int argc, char *argv[])
{
	int c;

	/* Get Program Name */
	if ((g_prog_name = strrchr(argv[0], '/')) == NULL) {
		g_prog_name = argv[0];
	} else {
		g_prog_name++;
	}

	while ((c = getopt(argc, argv, ":d:")) != -1) {
		switch (c) {
		case 'd':
			g_debuglevel = atoi(optarg);
			if ((g_debuglevel < 0) || (g_debuglevel > 2)) {
				g_debuglevel = 0;
			}
			break;

		case ':':
			syslog(LOG_ERR,
			    "missed argument for option %c.", optopt);
			break;

		case '?':
			syslog(LOG_ERR, "unrecognized option %c.", optopt);
			break;
		}
	}

	s_acpihpd_hdl = NULL;

	/* Check the daemon running lock and initialize the signal */
	if (daemon_init() != 0) {
		debug_print(0, "%s could not startup!", g_prog_name);
		exit(SMF_EXIT_ERR_FATAL);
	}

	/* Subscribe to the hotplug event */
	if (acpihpd_init() != 0) {
		debug_print(0, "%s could not startup!", g_prog_name);
		daemon_quit(SMF_EXIT_ERR_FATAL);
	}

	debug_print(2, "daemon is running.");
	/*CONSTCOND*/
	while (1) {
		(void) pause();
	}

	return (SMF_EXIT_OK);
}

static int
daemon_init(void)
{
	int	i, ret;
	pid_t	pid;
	char	pid_str[32];

	if (geteuid() != 0) {
		debug_print(0, "must be root to execute %s", g_prog_name);
		return (1);
	}

	if ((pid = fork()) < 0) {
		return (1);
	}

	if (pid > 0) {
		/* Parent to exit. */
		exit(SMF_EXIT_OK);
	}

	(void) setsid();
	(void) chdir("/");
	(void) umask(0);
	(void) closefrom(0);
	(void) open("/dev/null", O_RDONLY);
	(void) open("/dev/null", O_WRONLY);
	(void) dup(1);
	(void) openlog(g_prog_name, LOG_PID, LOG_DAEMON);

	/*
	 * Create the lock file for singleton
	 */
	if ((s_pid_fd = open(ACPIHPD_PID_FILE, O_RDWR | O_CREAT, 0644)) < 0) {
		debug_print(0, "could not create pid file: %s",
		    strerror(errno));
		return (1);
	}

	if (lockf(s_pid_fd, F_TLOCK, 0L) < 0) {
		if (errno == EACCES || errno == EAGAIN) {
			debug_print(0, "another acpihpd is already running");
		} else {
			debug_print(0, "could not lock pid file");
		}

		return (1);
	}

	(void) ftruncate(s_pid_fd, 0);
	i = sprintf(pid_str, "%ld", (long)getpid());
	while ((ret = write(s_pid_fd, pid_str, i)) != i) {
		if (errno == EINTR) {
			continue;
		}
		if (ret < 0) {
			debug_print(0, "pid file write failed: %s",
			    strerror(errno));
			return (1);
		}
	}

	if (set_sig_handler(SIGTERM, (sig_handler_t *)daemon_quit) != 0) {
		debug_print(2, "could not set signal handler(SIGTERM)");
		return (1);
	}

	if (set_sig_handler(SIGQUIT, (sig_handler_t *)daemon_quit) != 0) {
		debug_print(2, "could not set signal handler(SIGQUIT)");
		return (1);
	}

	if (set_sig_handler(SIGINT, (sig_handler_t *)daemon_quit) != 0) {
		debug_print(2, "could not set signal handler(SIGINT)");
		return (1);
	}

	if (set_sig_handler(SIGCHLD, SIG_IGN) != 0) {
		debug_print(2, "could not set signal handler(SIGCHLD)");
		return (1);
	}

	return (0);
}

static void
daemon_quit(int signo)
{
	int status = 0;
	id_t pgid;

	debug_print(1, "daemon quit [signal#:%d].", signo);

	acpihpd_fini();
	(void) set_sig_handler(SIGTERM, SIG_IGN);
	pgid = getpgrp();
	(void) kill(-pgid, SIGTERM);
	(void) close(s_pid_fd);
	(void) unlink(ACPIHPD_PID_FILE);

	if (signo < 0) {
		status = signo;
	}
	_exit(status);
}

static int
set_sig_handler(int sig, sig_handler_t *handler)
{
	struct sigaction act;

	act.sa_handler = handler;
	act.sa_flags = 0;
	if (sig == SIGCHLD && handler == SIG_IGN) {
		act.sa_flags |= SA_NOCLDWAIT;
	}

	(void) sigemptyset(&act.sa_mask);
	if (sigaction(sig, &act, NULL) < 0) {
		return (1);
	}

	return (0);
}

static int
acpihpd_init(void)
{
	const char *subclass = ESC_DR_REQ;

	debug_print(2, "acpihpd_init");

	if ((s_acpihpd_hdl = sysevent_bind_handle(acpihpd_event)) == NULL) {
		debug_print(2, "could not bind to sysevent.");
		return (-1);
	}

	if (sysevent_subscribe_event(s_acpihpd_hdl, EC_DR, &subclass, 1) != 0) {
		debug_print(2, "could not subscribe an event.");
		sysevent_unbind_handle(s_acpihpd_hdl);
		s_acpihpd_hdl = NULL;
		return (-1);
	}

	return (0);
}

static void
acpihpd_fini(void)
{
	debug_print(2, "acpihpd_fini");

	if (s_acpihpd_hdl != NULL) {
		sysevent_unsubscribe_event(s_acpihpd_hdl, EC_DR);
		sysevent_unbind_handle(s_acpihpd_hdl);
	}
}

static void
acpihpd_event(sysevent_t *ev)
{
	debug_print(2, "*** got an event ***");

	/* Inform cfgadm of the hot-plug event. */
	notify_hotplug(ev);
}

void
debug_print(int level, const char *fmt, ...)
{
	va_list ap;
	int pri, pr_out = 0;

	if (level <= g_debuglevel) {
		switch (level) {
		case 0:
			pri = LOG_ERR;
			pr_out = 1;
			break;

		case 1:
			pri = LOG_NOTICE;
			pr_out = 1;
			break;

		case 2:
			pri = LOG_DEBUG;
			pr_out = 1;
			break;
		}

		if (pr_out) {
			va_start(ap, fmt);
			vsyslog(pri, fmt, ap);
			va_end(ap);
		}
	}
}
