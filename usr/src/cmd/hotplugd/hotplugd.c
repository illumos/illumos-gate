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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdarg.h>
#include <strings.h>
#include <syslog.h>
#include <priv.h>
#include <wait.h>
#include <getopt.h>
#include <synch.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <libhotplug.h>
#include <libhotplug_impl.h>
#include "hotplugd_impl.h"

/*
 * Define long options for command line.
 */
static const struct option lopts[] = {
	{ "help",	no_argument,	0, '?' },
	{ "version",	no_argument,	0, 'V' },
	{ "debug",	no_argument,	0, 'd' },
	{ 0, 0, 0, 0 }
};

/*
 * Local functions.
 */
static void		usage(void);
static boolean_t	check_privileges(void);
static int		daemonize(void);
static void		init_signals(void);
static void		signal_handler(int signum);
static void		shutdown_daemon(void);

/*
 * Global variables.
 */
static char		*prog;
static char		version[] = "1.0";
static boolean_t	log_flag = B_FALSE;
static boolean_t	debug_flag = B_FALSE;
static boolean_t	exit_flag = B_FALSE;
static sema_t		signal_sem;

/*
 * main()
 *
 *	The hotplug daemon is designed to be a background daemon
 *	controlled by SMF.  So by default it will daemonize and
 *	do some coordination with its parent process in order to
 *	indicate proper success or failure back to SMF.  And all
 *	output will be sent to syslog.
 *
 *	But if given the '-d' command line option, it will instead
 *	run in the foreground in a standalone, debug mode.  Errors
 *	and additional debug messages will be printed to the controlling
 *	terminal instead of to syslog.
 */
int
main(int argc, char *argv[])
{
	int	opt;
	int	pfd;
	int	status;

	if ((prog = strrchr(argv[0], '/')) == NULL)
		prog = argv[0];
	else
		prog++;

	/* Check privileges */
	if (!check_privileges()) {
		(void) fprintf(stderr, "Insufficient privileges.  "
		    "(All privileges are required.)\n");
		return (-1);
	}

	/* Process options  */
	while ((opt = getopt_clip(argc, argv, "dV?", lopts, NULL)) != -1) {
		switch (opt) {
		case 'd':
			debug_flag = B_TRUE;
			break;
		case 'V':
			(void) printf("%s: Version %s\n", prog, version);
			return (0);
		default:
			if (optopt == '?') {
				usage();
				return (0);
			}
			(void) fprintf(stderr, "Unrecognized option '%c'.\n",
			    optopt);
			usage();
			return (-1);
		}
	}

	/* Initialize semaphore for daemon shutdown */
	if (sema_init(&signal_sem, 1, USYNC_THREAD, NULL) != 0)
		exit(EXIT_FAILURE);

	/* Initialize signal handling */
	init_signals();

	/* Daemonize, if not in DEBUG mode */
	if (!debug_flag)
		pfd = daemonize();

	/* Initialize door service */
	if (!door_server_init()) {
		if (!debug_flag) {
			status = EXIT_FAILURE;
			(void) write(pfd, &status, sizeof (status));
			(void) close(pfd);
		}
		exit(EXIT_FAILURE);
	}

	/* Daemon initialized */
	if (!debug_flag) {
		status = 0;
		(void) write(pfd, &status, sizeof (status));
		(void) close(pfd);
	}

	/* Note that daemon is running */
	log_info("hotplug daemon started.\n");

	/* Wait for shutdown signal */
	while (!exit_flag)
		(void) sema_wait(&signal_sem);

	shutdown_daemon();
	return (0);
}

/*
 * usage()
 *
 *	Print a brief usage synopsis for the command line options.
 */
static void
usage(void)
{
	(void) printf("Usage: %s [-d]\n", prog);
}

/*
 * check_privileges()
 *
 *	Check if the current process has enough privileges
 *	to run the daemon.  Note that all privileges are
 *	required in order for RCM interactions to work.
 */
static boolean_t
check_privileges(void)
{
	priv_set_t	*privset;
	boolean_t	rv = B_FALSE;

	if ((privset = priv_allocset()) != NULL) {
		if (getppriv(PRIV_EFFECTIVE, privset) == 0) {
			rv = priv_isfullset(privset);
		}
		priv_freeset(privset);
	}

	return (rv);
}

/*
 * daemonize()
 *
 *	Fork the daemon process into the background, and detach from
 *	the controlling terminal.  Setup a shared pipe that will later
 *	be used to report startup status to the parent process.
 */
static int
daemonize(void)
{
	int		status;
	int		pfds[2];
	pid_t		pid;
	sigset_t	set;
	sigset_t	oset;

	/*
	 * Temporarily block all signals.  They will remain blocked in
	 * the parent, but will be unblocked in the child once it has
	 * notified the parent of its startup status.
	 */
	(void) sigfillset(&set);
	(void) sigdelset(&set, SIGABRT);
	(void) sigprocmask(SIG_BLOCK, &set, &oset);

	/* Create the shared pipe */
	if (pipe(pfds) == -1) {
		log_err("Cannot create pipe (%s)\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

	/* Fork the daemon process */
	if ((pid = fork()) == -1) {
		log_err("Cannot fork daemon process (%s)\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

	/* Parent:  waits for exit status from child. */
	if (pid > 0) {
		(void) close(pfds[1]);
		if (read(pfds[0], &status, sizeof (status)) == sizeof (status))
			_exit(status);
		if ((waitpid(pid, &status, 0) == pid) && WIFEXITED(status))
			_exit(WEXITSTATUS(status));
		log_err("Failed to spawn daemon process.\n");
		_exit(EXIT_FAILURE);
	}

	/* Child continues... */

	(void) setsid();
	(void) chdir("/");
	(void) umask(CMASK);
	(void) sigprocmask(SIG_SETMASK, &oset, NULL);
	(void) close(pfds[0]);

	/* Detach from controlling terminal */
	(void) close(0);
	(void) close(1);
	(void) close(2);
	(void) open("/dev/null", O_RDONLY);
	(void) open("/dev/null", O_WRONLY);
	(void) open("/dev/null", O_WRONLY);

	/* Use syslog for future messages */
	log_flag = B_TRUE;
	openlog(prog, LOG_PID, LOG_DAEMON);

	return (pfds[1]);
}

/*
 * init_signals()
 *
 *	Initialize signal handling.
 */
static void
init_signals(void)
{
	struct sigaction	act;
	sigset_t		set;

	(void) sigfillset(&set);
	(void) sigdelset(&set, SIGABRT);

	(void) sigfillset(&act.sa_mask);
	act.sa_handler = signal_handler;
	act.sa_flags = 0;

	(void) sigaction(SIGTERM, &act, NULL);
	(void) sigaction(SIGHUP, &act, NULL);
	(void) sigaction(SIGINT, &act, NULL);
	(void) sigaction(SIGPIPE, &act, NULL);

	(void) sigdelset(&set, SIGTERM);
	(void) sigdelset(&set, SIGHUP);
	(void) sigdelset(&set, SIGINT);
	(void) sigdelset(&set, SIGPIPE);
}

/*
 * signal_handler()
 *
 *	Most signals cause the hotplug daemon to shut down.
 *	Shutdown is triggered using a semaphore to wake up
 *	the main thread for a clean exit.
 *
 *	Except SIGPIPE is used to coordinate between the parent
 *	and child processes when the daemon first starts.
 */
static void
signal_handler(int signum)
{
	log_info("Received signal %d.\n", signum);

	switch (signum) {
	case 0:
	case SIGPIPE:
		break;
	default:
		exit_flag = B_TRUE;
		(void) sema_post(&signal_sem);
		break;
	}
}

/*
 * shutdown_daemon()
 *
 *	Perform a clean shutdown of the daemon.
 */
static void
shutdown_daemon(void)
{
	log_info("Hotplug daemon shutting down.\n");

	door_server_fini();

	if (log_flag)
		closelog();

	(void) sema_destroy(&signal_sem);
}

/*
 * log_err()
 *
 *	Display an error message.  Use syslog if in daemon
 *	mode, otherwise print to stderr when in debug mode.
 */
/*PRINTFLIKE1*/
void
log_err(char *fmt, ...)
{
	va_list	ap;

	va_start(ap, fmt);
	if (debug_flag || !log_flag)
		(void) vfprintf(stderr, fmt, ap);
	else
		vsyslog(LOG_ERR, fmt, ap);
	va_end(ap);
}

/*
 * log_info()
 *
 *	Display an information message.  Use syslog if in daemon
 *	mode, otherwise print to stdout when in debug mode.
 */
/*PRINTFLIKE1*/
void
log_info(char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	if (debug_flag || !log_flag)
		(void) vfprintf(stdout, fmt, ap);
	else
		vsyslog(LOG_INFO, fmt, ap);
	va_end(ap);
}

/*
 * hp_dprintf()
 *
 *	Print a debug tracing statement.  Only works in debug
 *	mode, and always prints to stdout.
 */
/*PRINTFLIKE1*/
void
hp_dprintf(char *fmt, ...)
{
	va_list	ap;

	if (debug_flag) {
		va_start(ap, fmt);
		(void) vprintf(fmt, ap);
		va_end(ap);
	}
}
