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
 * The ipmgmtd daemon is started by ip-interface-management SMF service. This
 * daemon is used to manage, mapping of 'address object' to 'interface name' and
 * 'logical interface number', on which the address is created. It also provides
 * a means to update the ipadm persistent data-store.
 *
 * The daemon tracks the <addrobj, lifname> mapping in-memory using a linked
 * list `aobjmap'. Access to this list is synchronized using a readers-writers
 * lock. The active <addrobj, lifname> mapping is kept in
 * /etc/svc/volatile/ipadm/aobjmap.conf cache file, so that the mapping can be
 * recovered when ipmgmtd exits for some reason (e.g., when ipmgmtd is restarted
 * using svcadm or accidentally killed).
 *
 * Today, the persistent configuration of interfaces, addresses and protocol
 * properties is kept in /etc/ipadm/ipadm.conf. The access to the persistent
 * data store is synchronized using reader-writers lock `ipmgmt_dbconf_lock'.
 *
 * The communication between the library, libipadm.so and the daemon, is through
 * doors RPC. The library interacts with the daemon using the commands defined
 * by `ipmgmt_door_cmd_type_t'. Further any 'write' operation would require
 * the `NETWORK_INTERFACE_CONFIG_AUTH' authorization.
 *
 * On reboot, the aforementioned SMF service starts the daemon before any other
 * networking service that configures network IP interfaces is started.
 * Afterwards, the network/physical SMF script instantiates the persisted
 * network interfaces, interface properties and addresses.
 */

#include <errno.h>
#include <fcntl.h>
#include <priv_utils.h>
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <strings.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <unistd.h>
#include "ipmgmt_impl.h"

const char		*progname;

/* readers-writers lock for reading/writing daemon data store */
pthread_rwlock_t	ipmgmt_dbconf_lock;

/* tracks address object to {ifname|logical number|interface id} mapping */
ipmgmt_aobjmap_list_t	aobjmap;

/* used to communicate failure to parent process, which spawned the daemon */
static int		pfds[2];

/* file descriptor to IPMGMT_DOOR */
static int		ipmgmt_door_fd = -1;

static void		ipmgmt_exit(int);
static int		ipmgmt_init();
static int		ipmgmt_init_privileges();

static int
ipmgmt_db_init()
{
	int		fd, err;

	/* creates the address object data store, if it doesn't exist */
	if ((fd = open(ADDROBJ_MAPPING_DB_FILE, O_CREAT|O_RDONLY,
	    IPADM_FILE_MODE)) == -1) {
		err = errno;
		ipmgmt_log(LOG_ERR, "could not open %s: %s",
		    ADDROBJ_MAPPING_DB_FILE, strerror(err));
		return (err);
	}
	(void) close(fd);

	aobjmap.aobjmap_head = NULL;
	(void) pthread_rwlock_init(&aobjmap.aobjmap_rwlock, NULL);

	/*
	 * If the daemon is recovering from a crash or restart, read the
	 * address object to logical interface mapping and build an in-memory
	 * representation of the mapping. That is, build `aobjmap' structure
	 * from address object data store.
	 */
	if ((err = ipadm_rw_db(ipmgmt_aobjmap_init, NULL,
	    ADDROBJ_MAPPING_DB_FILE, 0, IPADM_DB_READ)) != 0) {
		/* if there was nothing to initialize, it's fine */
		if (err != ENOENT)
			return (err);
		err = 0;
	}

	(void) pthread_rwlock_init(&ipmgmt_dbconf_lock, NULL);
	return (err);
}

static int
ipmgmt_door_init()
{
	int fd;
	int err;

	/* create the door file for ipmgmtd */
	if ((fd = open(IPMGMT_DOOR, O_CREAT|O_RDONLY, IPADM_FILE_MODE)) == -1) {
		err = errno;
		ipmgmt_log(LOG_ERR, "could not open %s: %s",
		    IPMGMT_DOOR, strerror(err));
		return (err);
	}
	(void) close(fd);

	if ((ipmgmt_door_fd = door_create(ipmgmt_handler, NULL,
	    DOOR_REFUSE_DESC | DOOR_NO_CANCEL)) == -1) {
		err = errno;
		ipmgmt_log(LOG_ERR, "failed to create door: %s", strerror(err));
		return (err);
	}
	/*
	 * fdetach first in case a previous daemon instance exited
	 * ungracefully.
	 */
	(void) fdetach(IPMGMT_DOOR);
	if (fattach(ipmgmt_door_fd, IPMGMT_DOOR) != 0) {
		err = errno;
		ipmgmt_log(LOG_ERR, "failed to attach door to %s: %s",
		    IPMGMT_DOOR, strerror(err));
		goto fail;
	}
	return (0);
fail:
	(void) door_revoke(ipmgmt_door_fd);
	ipmgmt_door_fd = -1;
	return (err);
}

static void
ipmgmt_door_fini()
{
	if (ipmgmt_door_fd == -1)
		return;

	(void) fdetach(IPMGMT_DOOR);
	if (door_revoke(ipmgmt_door_fd) == -1) {
		ipmgmt_log(LOG_ERR, "failed to revoke access to door %s: %s",
		    IPMGMT_DOOR, strerror(errno));
	}
}

static int
ipmgmt_init()
{
	int err;

	if (signal(SIGTERM, ipmgmt_exit) == SIG_ERR ||
	    signal(SIGINT, ipmgmt_exit) == SIG_ERR) {
		err = errno;
		ipmgmt_log(LOG_ERR, "signal() for SIGTERM/INT failed: %s",
		    strerror(err));
		return (err);
	}
	if ((err = ipmgmt_db_init()) != 0 || (err = ipmgmt_door_init()) != 0)
		return (err);
	return (0);
}

/*
 * This is called by the child process to inform the parent process to
 * exit with the given return value.
 */
static void
ipmgmt_inform_parent_exit(int rv)
{
	if (write(pfds[1], &rv, sizeof (int)) != sizeof (int)) {
		ipmgmt_log(LOG_WARNING,
		    "failed to inform parent process of status: %s",
		    strerror(errno));
		(void) close(pfds[1]);
		exit(EXIT_FAILURE);
	}
	(void) close(pfds[1]);
}

/*ARGSUSED*/
static void
ipmgmt_exit(int signo)
{
	(void) close(pfds[1]);
	ipmgmt_door_fini();
	exit(EXIT_FAILURE);
}

/*
 * Set the uid of this daemon to the "ipadm" user. Finish the following
 * operations before setuid() because they need root privileges:
 *
 *    - create the /etc/svc/volatile/ipadm directory;
 *    - change its uid/gid to "ipadm"/"sys";
 */
static int
ipmgmt_init_privileges()
{
	struct stat	statbuf;
	int err;

	/* create the IPADM_TMPFS_DIR directory */
	if (stat(IPADM_TMPFS_DIR, &statbuf) < 0) {
		if (mkdir(IPADM_TMPFS_DIR, (mode_t)0755) < 0) {
			err = errno;
			goto fail;
		}
	} else {
		if ((statbuf.st_mode & S_IFMT) != S_IFDIR) {
			err = ENOTDIR;
			goto fail;
		}
	}

	if ((chmod(IPADM_TMPFS_DIR, 0755) < 0) ||
	    (chown(IPADM_TMPFS_DIR, UID_NETADM, GID_NETADM) < 0)) {
		err = errno;
		goto fail;
	}

	/*
	 * limit the privileges of this daemon and set the uid of this
	 * daemon to UID_NETADM
	 */
	if (__init_daemon_priv(PU_RESETGROUPS|PU_CLEARLIMITSET, UID_NETADM,
	    GID_NETADM, NULL) == -1) {
		err = EPERM;
		goto fail;
	}

	return (0);
fail:
	(void) ipmgmt_log(LOG_ERR, "failed to initialize the daemon: %s",
	    strerror(err));
	return (err);
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

/*
 * We cannot use libc's daemon() because the door we create is associated with
 * the process ID. If we create the door before the call to daemon(), it will
 * be associated with the parent and it's incorrect. On the other hand if we
 * create the door later, after the call to daemon(), parent process exits
 * early and gives a false notion to SMF that 'ipmgmtd' is up and running,
 * which is incorrect. So, we have our own daemon() equivalent.
 */
static boolean_t
ipmgmt_daemonize(void)
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
		 * Parent should not exit early, it should wait for the child
		 * to return Success/Failure. If the parent exits early, then
		 * SMF will think 'ipmgmtd' is up and would start all the
		 * depended services.
		 *
		 * If the child process exits unexpectedly, read() returns -1.
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

	/* close all files except pfds[1] */
	(void) fdwalk(closefunc, NULL);
	(void) chdir("/");
	openlog(progname, LOG_PID, LOG_DAEMON);
	return (B_TRUE);
}

int
main(int argc, char *argv[])
{
	int opt;
	boolean_t fg = B_FALSE;

	progname = strrchr(argv[0], '/');
	if (progname != NULL)
		progname++;
	else
		progname = argv[0];

	/* Process options */
	while ((opt = getopt(argc, argv, "f")) != EOF) {
		switch (opt) {
		case 'f':
			fg = B_TRUE;
			break;
		default:
			(void) fprintf(stderr, "Usage: %s [-f]\n", progname);
			return (EXIT_FAILURE);
		}
	}

	if (!fg && getenv("SMF_FMRI") == NULL) {
		(void) fprintf(stderr,
		    "ipmgmtd is a smf(5) managed service and cannot be run "
		    "from the command line.\n");
		return (EINVAL);
	}

	if (!fg && !ipmgmt_daemonize())
		return (EXIT_FAILURE);

	if (ipmgmt_init_privileges() != 0)
		goto child_out;

	if (ipmgmt_init() != 0)
		goto child_out;

	/* Inform the parent process that it can successfully exit */
	ipmgmt_inform_parent_exit(EXIT_SUCCESS);

	for (;;)
		(void) pause();

child_out:
	/* return from main() forcibly exits an MT process */
	ipmgmt_inform_parent_exit(EXIT_FAILURE);
	return (EXIT_FAILURE);
}
