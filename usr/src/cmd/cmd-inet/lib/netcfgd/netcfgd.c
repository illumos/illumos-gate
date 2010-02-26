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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * netcfgd - network configuration daemon.  At present, this daemon implements
 * the configuration backend for libnwam (via calls to nwam_backend_init()
 * and nwam_backend_fini()).  Initialization of the backend creates a  door
 * that libnwam calls use to read, update and destroy persistent configuration.
 *
 * More long-term, netcfgd will be used to manage other sources of configuration
 * data and the backend functionality currently contained in libnwam will be
 * generalized.
 */

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <wait.h>
#include <libnwam_priv.h>
#include <libnwam.h>

static const char *progname;
static boolean_t fg = B_FALSE;

/*
 * This function allows you to drop a dtrace probe here and trace
 * complete strings (not just those containing formatting).  It's
 * important that we actually format the strings so we could trace them
 * even if we choose not to log them.
 */
static void
log_out(int severity, const char *str)
{
	if (fg) {
		(void) fprintf(stderr, "%s: %s\n", progname, str);
	} else {
		syslog(severity, str);
	}
}

/* PRINTFLIKE2 */
void
nlog(int severity, const char *fmt, ...)
{
	va_list ap;
	char *vbuf;

	va_start(ap, fmt);
	if (vasprintf(&vbuf, fmt, ap) != -1) {
		log_out(severity, vbuf);
		free(vbuf);
	}
	va_end(ap);
}

static void
start_logging(void)
{
	if (!fg)
		openlog(progname, LOG_PID, LOG_DAEMON);

	nlog(LOG_DEBUG, "%s started", progname);
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
	if ((pid = fork()) == -1) {
		nlog(LOG_ERR, "fork 1 failed");
		exit(EXIT_FAILURE);
	}
	if (pid != 0) {
		(void) wait(NULL);
		nlog(LOG_DEBUG, "child %ld exited, daemonizing", pid);
		_exit(0);
	}
	if (setsid() == (pid_t)-1) {
		nlog(LOG_ERR, "setsid");
		exit(EXIT_FAILURE);
	}
	if ((pid = fork()) == -1) {
		nlog(LOG_ERR, "fork 2 failed");
		exit(EXIT_FAILURE);
	}
	if (pid != 0) {
		_exit(0);
	}
	(void) chdir("/");
	(void) umask(022);
}

/* ARGSUSED */
static void
graceful_shutdown(int signo)
{
	nwam_backend_fini();
	exit(EXIT_SUCCESS);
}

int
main(int argc, char *argv[])
{
	int c;
	nwam_error_t err;

	if ((progname = strrchr(argv[0], '/')) == NULL)
		progname = argv[0];
	else
		progname++;

	while ((c = getopt(argc, argv, "f")) != -1) {
		switch (c) {
		case 'f':
			fg = B_TRUE;
			break;
		default:
			(void) fprintf(stderr, "%s: unrecognized option %c\n",
			    progname, optopt);
			exit(EXIT_FAILURE);
		}
	}
	start_logging();

	if (!fg)
		daemonize();

	(void) signal(SIGTERM, graceful_shutdown);
	(void) signal(SIGQUIT, graceful_shutdown);
	(void) signal(SIGPIPE, SIG_IGN);
	(void) signal(SIGCHLD, SIG_IGN);
	(void) atexit(nwam_backend_fini);

	if ((err = nwam_backend_init()) != NWAM_SUCCESS) {
		nlog(LOG_ERR,
		    "couldn't initialize libnwam backend: %s",
		    nwam_strerror(err));
		exit(EXIT_FAILURE);
	}

	for (;;)
		(void) pause();

	/* NOTREACHED */
	return (EXIT_SUCCESS);
}
