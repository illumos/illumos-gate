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
 * bridged - bridging control daemon.
 */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <string.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <syslog.h>
#include <locale.h>
#include <stropts.h>

#include "global.h"

boolean_t debugging;
uint32_t tablemax;
const char *instance_name = "default";

struct pollfd *fdarray;

dladm_handle_t dlhandle;

boolean_t shutting_down;

static pthread_t sighand;

/*
 * engine_lock is held while the main loop is busy calling librstp functions.
 * Door threads take the lock to protect the library from reentrancy.
 */
static pthread_mutex_t engine_lock = PTHREAD_MUTEX_INITIALIZER;

/*
 * These wrapper functions allow the other components in the daemon to remain
 * ignorant of pthreads details.
 */
int
lock_engine(void)
{
	return (pthread_mutex_lock(&engine_lock));
}

void
unlock_engine(void)
{
	(void) pthread_mutex_unlock(&engine_lock);
}

/*
 * Utility function for STREAMS ioctls.
 */
ssize_t
strioctl(int fd, int cmd, void *buf, size_t buflen)
{
	int retv;
	struct strioctl ic;

	ic.ic_cmd = cmd;
	ic.ic_timout = 0;
	ic.ic_dp = buf;
	ic.ic_len = buflen;
	if ((retv = ioctl(fd, I_STR, &ic)) != 0)
		return (retv);
	else
		return (ic.ic_len);
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
		_exit(EXIT_SUCCESS);
	}
	if (setsid() == (pid_t)-1) {
		syslog(LOG_ERR, "setsid");
		exit(EXIT_FAILURE);
	}
	if ((pid = fork()) == (pid_t)-1) {
		syslog(LOG_ERR, "fork 2 failed");
		exit(EXIT_FAILURE);
	}
	if (pid != 0)
		_exit(EXIT_SUCCESS);
	(void) chdir("/");
	(void) umask(022);
}

static void *
sighandler(void *arg)
{
	sigset_t sigset;
	int sig;
	int sigfd = (int)(uintptr_t)arg;

	(void) sigfillset(&sigset);

	for (;;) {
		sig = sigwait(&sigset);
		switch (sig) {
		case SIGHUP:
			(void) write(sigfd, "", 1);
			break;

		default:
			if (debugging)
				syslog(LOG_NOTICE, "%s signal, shutting down",
				    strsignal(sig));
			shutting_down = B_TRUE;
			break;
		}

		/* if we're shutting down, exit this thread */
		if (shutting_down)
			return (NULL);
	}
}

static void
init_signalhandling(void)
{
	pthread_attr_t attr;
	int err;
	sigset_t new;
	int fildes[2];

	if ((fdarray = malloc(FDOFFSET * sizeof (struct pollfd))) == NULL) {
		syslog(LOG_ERR, "unable to allocate fdarray: %m");
		exit(EXIT_FAILURE);
	}
	if (pipe(fildes) != 0) {
		syslog(LOG_ERR, "unable to create signal pipe: %m");
		exit(EXIT_FAILURE);
	}
	fdarray[0].fd = fildes[0];
	fdarray[0].events = POLLIN;
	assert(control_fd != -1);
	fdarray[1].fd = control_fd;
	fdarray[1].events = POLLIN;

	(void) sigfillset(&new);
	(void) pthread_sigmask(SIG_BLOCK, &new, NULL);
	(void) pthread_attr_init(&attr);
	(void) pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
	err = pthread_create(&sighand, &attr, sighandler,
	    (void *)(uintptr_t)fildes[1]);
	if (err != 0) {
		syslog(LOG_ERR, "cannot create signal handling thread: %s",
		    strerror(err));
		exit(EXIT_FAILURE);
	}
	(void) pthread_attr_destroy(&attr);
}

int
main(int argc, char **argv)
{
	dladm_status_t status;
	char buf[DLADM_STRSIZE];

	(void) setlocale(LC_ALL, "");
	(void) textdomain(TEXT_DOMAIN);

	shutting_down = B_FALSE;
	openlog("bridged", LOG_PID | LOG_NDELAY, LOG_DAEMON);

	if (argc != 2) {
		syslog(LOG_ERR, "instance name is required");
		exit(EXIT_FAILURE);
	}

	instance_name = argv[1];

	if ((status = dladm_open(&dlhandle)) != DLADM_STATUS_OK) {
		syslog(LOG_ERR, "%s: unable to open datalink control: %s",
		    instance_name, dladm_status2str(status, buf));
		exit(EXIT_FAILURE);
	}

	status = dladm_bridge_get_privprop(instance_name, &debugging,
	    &tablemax);
	if (status != DLADM_STATUS_OK) {
		syslog(LOG_ERR, "%s: unable to read properties: %s",
		    instance_name, dladm_status2str(status, buf));
		exit(EXIT_FAILURE);
	}

	/* Get the properties once so that we have the right initial values */
	rstp_init();

	open_bridge_control();

	daemonize();

	init_signalhandling();
	init_door();

	if (debugging)
		syslog(LOG_INFO, "bridged started: instance %s", instance_name);

	event_loop();
	(void) pthread_cancel(sighand);
	(void) pthread_join(sighand, NULL);

	return (0);
}
