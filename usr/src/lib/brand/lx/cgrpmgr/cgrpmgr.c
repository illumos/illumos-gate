/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2015 Joyent, Inc.
 */

/*
 * The cgrpmgr is a user-level daemon process associated with a specific cgroup
 * fs mount. It's only job is to run the release_agent when a cgroup becomes
 * empty and notify_on_release is enabled.
 */

#include <stdarg.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/statvfs.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

#include <cgrps.h>

static void
run_agent(char *agent, char *arg)
{
	char *argv[3];
	char *cmdp;

	/*
	 * The parent does nothing.
	 */
	if (fork() != 0)
		return;

	/*
	 * Child - run the agent.
	 */
	(void) setsid();

	cmdp = strrchr(agent, '/');
	if (cmdp == NULL) {
		cmdp = agent;
	} else {
		cmdp++;
	}

	argv[0] = cmdp;
	argv[1] = arg;
	argv[2] = NULL;

	execv(agent, argv);
	/* Nothing can be done if the exec fails */
	exit(1);
}

int
main(int argc, char *argv[])
{
	int fd;
	int res;
	sigset_t set, oset;
	struct statvfs sb;
	char rel_agent[MAXPATHLEN];
	char cgrp_path[MAXPATHLEN];
	cgrpmgr_info_t cgmi;

	/*
	 * Start by daemonizing ourself.
	 */

	/* Close all open fd's */
	closefrom(0);

	clearenv();

	/*
	 * Block all signals except SIGCHLD since we don't want this code to
	 * respond to any signal (except, of course, the ones we can't block).
	 * By setting the SIGCHLD disposition to ignore our children will
	 * automatically be reaped.
	 */
	(void) sigfillset(&set);
	(void) sigdelset(&set, SIGCHLD);
	(void) sigdelset(&set, SIGABRT);
	(void) sigprocmask(SIG_BLOCK, &set, &oset);
	(void) signal(SIGCHLD, SIG_IGN);

	switch (fork1()) {
	case -1: /* uh-oh */
		exit(1);

	case 0:	/* child */
		break;

	default: /* parent */
		exit(0);
	}

	(void) setsid();
	(void) umask(0077);
	(void) chdir("/");

	if ((fd = open(argv[1], O_RDONLY)) < 0)
		exit(1);

	/*
	 * Sanity check the mount point we got.
	 */
	if (fstatvfs(fd, &sb) < 0 || strcmp(sb.f_basetype, "lx_cgroup") != 0)
		exit(1);

	cgmi.cgmi_pid = getpid();
	cgmi.cgmi_rel_agent_path = rel_agent;
	cgmi.cgmi_cgroup_path = cgrp_path;

	/*
	 * Now wait for and run the release agent each time we return from the
	 * ioctl. An error return indicates the fs has been unmounted and we
	 * should exit.
	 */
	for (;;) {
		/*
		 * Block in the kernel until a cgroup becomes empty.
		 */
		res = ioctl(fd, CGRPFS_GETEVNT, &cgmi);

		/*
		 * EIO indicates we should quit but any other error implies
		 * we did something wrong (which means a bug), so simply
		 * terminate on any error.
		 */
		if (res != 0) {
			if (errno == EIO)
				exit(0);
			abort();
		}

		run_agent(rel_agent, cgrp_path);
	}

	return (0);
}
