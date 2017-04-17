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
 * Copyright (c) 2016 by Delphix. All rights reserved.
 */

/*
 * Steal memory from the kernel, forcing the ARC to decrease in size, and hold
 * it until the process receives a signal.
 */

#include <stdio.h>
#include <sys/types.h>
#include <sys/shm.h>
#include <strings.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>

static void
usage(char *progname)
{
	(void) fprintf(stderr, "Usage: %s -f <bytes>\n", progname);
	exit(1);
}

static void
fail(char *err, int rval)
{
	perror(err);
	exit(rval);
}

static void
daemonize(void)
{
	pid_t	pid;

	if ((pid = fork()) < 0) {
		fail("fork", 1);
	} else if (pid != 0) {
		(void) fprintf(stdout, "%ld\n", pid);
		exit(0);
	}

	(void) setsid();
	(void) close(0);
	(void) close(1);
	(void) close(2);
}

int
main(int argc, char *argv[])
{
	int		c;
	boolean_t	fflag = B_FALSE;
	char		*prog = argv[0];
	long long	size;
	char		*stroll_leftovers;
	int		shm_id;
	void		*shm_attached;

	while ((c = getopt(argc, argv, "f")) != -1) {
		switch (c) {
		/* Run in the foreground */
		case 'f':
			fflag = B_TRUE;
			break;
		default:
			usage(prog);
		}
	}

	argc -= optind;
	argv += optind;

	if (argc != 1)
		usage(prog);
	size = strtoll(argv[0], &stroll_leftovers, 10);
	if (size <= 0)
		fail("invalid size in bytes", 1);

	if ((shm_id = shmget(IPC_PRIVATE, size, IPC_CREAT|IPC_EXCL)) == -1)
		fail("shmget", 1);
	if ((shm_attached = shmat(shm_id, NULL, SHM_SHARE_MMU)) == (void *)-1)
		fail("shmat", 1);

	if (fflag == B_FALSE)
		daemonize();
	(void) pause();

	/* NOTREACHED */
	return (0);
}
