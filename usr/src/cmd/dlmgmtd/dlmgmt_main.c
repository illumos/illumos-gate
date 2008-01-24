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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * The dlmgmtd daemon is started by the datalink-management SMF service.
 * This daemon is used to manage <link name, linkid> mapping and the
 * persistent datalink configuration.
 *
 * Today, the <link name, linkid> mapping and the persistent configuration
 * of datalinks is kept in /etc/dladm/datalink.conf, and the daemon keeps
 * a copy of the datalinks in the memory (see dlmgmt_id_avl and
 * dlmgmt_name_avl). The active <link name, linkid> mapping is kept in
 * /etc/svc/volatile cache file, so that the mapping can be recovered when
 * dlmgmtd exits for some reason (e.g., when dlmgmtd is accidentally killed).
 */

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <priv.h>
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <stropts.h>
#include <strings.h>
#include <syslog.h>
#include <sys/dld.h>
#include <unistd.h>
#include <libdlmgmt.h>
#include "dlmgmt_impl.h"

const char		*progname;
boolean_t		debug;
static int		pfds[2];
static char		dlmgmt_door_file[] = DLMGMT_DOOR;
static int		dlmgmt_door_fd = -1;

static int
dlmgmt_set_doorfd(boolean_t start)
{
	dld_ioc_door_t did;
	struct strioctl iocb;
	int fd;
	int err = 0;

	if ((fd = open(DLD_CONTROL_DEV, O_RDWR)) < 0)
		return (EINVAL);

	did.did_start_door = start;

	iocb.ic_cmd	= DLDIOC_DOORSERVER;
	iocb.ic_timout	= 0;
	iocb.ic_len	= sizeof (did);
	iocb.ic_dp	= (char *)&did;

	if (ioctl(fd, I_STR, &iocb) == -1)
		err = errno;

	(void) close(fd);
	return (err);
}

static int
dlmgmt_door_init()
{
	int err;

	if ((dlmgmt_door_fd = door_create(dlmgmt_handler, NULL,
	    DOOR_REFUSE_DESC | DOOR_NO_CANCEL)) == -1) {
		err = errno;
		dlmgmt_log(LOG_WARNING, "door_create() failed: %s",
		    strerror(err));
		return (err);
	}
	if (fattach(dlmgmt_door_fd, DLMGMT_DOOR) != 0) {
		err = errno;
		dlmgmt_log(LOG_WARNING, "fattach(%s) failed: %s",
		    DLMGMT_DOOR, strerror(err));
		goto fail;
	}
	if ((err = dlmgmt_set_doorfd(B_TRUE)) != 0) {
		dlmgmt_log(LOG_WARNING, "cannot set kernel doorfd: %s",
		    strerror(err));
		goto fail;
	}

	return (0);
fail:
	if (dlmgmt_door_fd != -1) {
		(void) door_revoke(dlmgmt_door_fd);
		dlmgmt_door_fd = -1;
	}
	(void) fdetach(DLMGMT_DOOR);
	return (err);
}

static void
dlmgmt_door_fini()
{
	(void) dlmgmt_set_doorfd(B_FALSE);
	if ((dlmgmt_door_fd != -1) && (door_revoke(dlmgmt_door_fd) == -1)) {
		dlmgmt_log(LOG_WARNING, "door_revoke(%s) failed: %s",
		    dlmgmt_door_file, strerror(errno));
	}
	(void) fdetach(DLMGMT_DOOR);
}

static int
dlmgmt_init()
{
	int err;

	if ((err = dlmgmt_linktable_init()) != 0)
		return (err);

	if ((err = dlmgmt_db_init()) != 0 || (err = dlmgmt_door_init()) != 0)
		dlmgmt_linktable_fini();

	return (err);
}

static void
dlmgmt_fini()
{
	dlmgmt_door_fini();
	dlmgmt_linktable_fini();
}

/*
 * This is called by the child process to inform the parent process to
 * exit with the given return value.
 */
static void
dlmgmt_inform_parent_exit(int rv)
{
	if (debug)
		return;

	if (write(pfds[1], &rv, sizeof (int)) != sizeof (int)) {
		dlmgmt_log(LOG_WARNING,
		    "dlmgmt_inform_parent_exit() failed: %s", strerror(errno));
		(void) close(pfds[1]);
		exit(EXIT_FAILURE);
	}
	(void) close(pfds[1]);
}

/*ARGSUSED*/
static void
dlmgmtd_exit(int signo)
{
	(void) close(pfds[1]);
	dlmgmt_fini();
	exit(EXIT_FAILURE);
}

static void
usage(void)
{
	(void) fprintf(stderr, "Usage: %s [-d]\n", progname);
	exit(EXIT_FAILURE);
}

static int
dlmgmt_setup_privs()
{
	priv_set_t *priv_set = NULL;
	char *p;

	priv_set = priv_allocset();
	if (priv_set == NULL || getppriv(PRIV_PERMITTED, priv_set) == -1) {
		dlmgmt_log(LOG_WARNING, "failed to get the permitted set of "
		    "privileges %s", strerror(errno));
		return (-1);
	}

	p = priv_set_to_str(priv_set, ',', 0);
	dlmgmt_log(LOG_DEBUG, "start with privs %s", p != NULL ? p : "Unknown");
	free(p);

	priv_emptyset(priv_set);
	(void) priv_addset(priv_set, "file_dac_write");
	(void) priv_addset(priv_set, "file_chown_self");
	(void) priv_addset(priv_set, "sys_mount");
	(void) priv_addset(priv_set, "sys_net_config");

	if (setppriv(PRIV_SET, PRIV_INHERITABLE, priv_set) == -1) {
		dlmgmt_log(LOG_WARNING, "failed to set the inheritable set of "
		    "privileges %s", strerror(errno));
		priv_freeset(priv_set);
		return (-1);
	}

	if (setppriv(PRIV_SET, PRIV_PERMITTED, priv_set) == -1) {
		dlmgmt_log(LOG_WARNING, "failed to set the permitted set of "
		    "privileges %s", strerror(errno));
		priv_freeset(priv_set);
		return (-1);
	}

	if (setppriv(PRIV_SET, PRIV_EFFECTIVE, priv_set) == -1) {
		dlmgmt_log(LOG_WARNING, "failed to set the effective set of "
		    "privileges %s", strerror(errno));
		priv_freeset(priv_set);
		return (-1);
	}

	priv_freeset(priv_set);
	return (0);
}

/*
 * Keep the pfds fd open, close other fds.
 */
/*ARGSUSED*/
static int
closefunc(void *arg, int fd)
{
	if (fd != pfds[1])
		(void) close(fd);
	return (0);
}

static boolean_t
dlmgmt_daemonize(void)
{
	pid_t pid;
	int rv;

	if (pipe(pfds) < 0) {
		(void) fprintf(stderr, "%s: pipe() failed: %s\n",
		    progname, strerror(errno));
		exit(EXIT_FAILURE);
	}

	if ((pid = fork()) == -1) {
		(void) fprintf(stderr, "%s: fork() failed: %s\n",
		    progname, strerror(errno));
		exit(EXIT_FAILURE);
	} else if (pid > 0) { /* Parent */
		(void) close(pfds[1]);

		/*
		 * Read the child process's return value from the pfds.
		 * If the child process exits unexpected, read() returns -1.
		 */
		if (read(pfds[0], &rv, sizeof (int)) != sizeof (int)) {
			(void) kill(pid, SIGKILL);
			rv = EXIT_FAILURE;
		}

		(void) close(pfds[0]);
		exit(rv);
	}

	/* Child */
	(void) close(pfds[0]);
	(void) setsid();

	/*
	 * Close all files except pfds[1].
	 */
	(void) fdwalk(closefunc, NULL);
	(void) chdir("/");
	openlog(progname, LOG_PID, LOG_DAEMON);
	return (B_TRUE);
}

int
main(int argc, char *argv[])
{
	int opt;

	progname = strrchr(argv[0], '/');
	if (progname != NULL)
		progname++;
	else
		progname = argv[0];

	/*
	 * Process options.
	 */
	while ((opt = getopt(argc, argv, "d")) != EOF) {
		switch (opt) {
		case 'd':
			debug = B_TRUE;
			break;
		default:
			usage();
		}
	}

	if (!debug && !dlmgmt_daemonize())
		return (EXIT_FAILURE);

	if (signal(SIGTERM, dlmgmtd_exit) == SIG_ERR) {
		dlmgmt_log(LOG_WARNING, "signal() for SIGTERM failed: %s",
		    strerror(errno));
		goto child_out;
	}

	if (dlmgmt_init() != 0)
		goto child_out;

	if (dlmgmt_setup_privs() != 0)
		goto child_out;

	/*
	 * Inform the parent process that it can successfully exit.
	 */
	dlmgmt_inform_parent_exit(EXIT_SUCCESS);

	for (;;)
		(void) pause();

child_out:
	/* return from main() forcibly exits an MT process */
	dlmgmt_inform_parent_exit(EXIT_FAILURE);
	return (EXIT_FAILURE);
}
