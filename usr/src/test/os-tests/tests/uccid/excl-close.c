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
 * Copyright 2019, Joyent, Inc.
 */

/*
 * Verify that if a child grabs an exclusive lock and calls exit, we can grab it
 * again.
 */

#include <err.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <strings.h>
#include <unistd.h>
#include <errno.h>
#include <sys/wait.h>

#include <sys/usb/clients/ccid/uccid.h>

int
main(int argc, char *argv[])
{
	int fd, estat;
	pid_t pid;
	uccid_cmd_txn_begin_t begin;

	if (argc != 2) {
		errx(EXIT_FAILURE, "missing required ccid path");
	}

	bzero(&begin, sizeof (begin));
	begin.uct_version = UCCID_CURRENT_VERSION;

	pid = fork();
	if (pid == 0) {
		fd = open(argv[1], O_RDWR);
		if (fd < 0) {
			err(EXIT_FAILURE, "failed to open %s", argv[1]);
		}

		if (ioctl(fd, UCCID_CMD_TXN_BEGIN, &begin) != 0) {
			err(EXIT_FAILURE, "failed to issue begin ioctl");
		}

		_exit(0);
	}

	estat = -1;
	if (waitpid(pid, &estat, 0) == -1) {
		err(EXIT_FAILURE, "failed to wait for pid %" _PRIdID, pid);
	}

	if (estat != 0) {
		errx(EXIT_FAILURE, "child exited with non-zero value (%d)",
		    estat);
	}

	fd = open(argv[1], O_RDWR);
	if (fd < 0) {
		err(EXIT_FAILURE, "failed to open %s", argv[1]);
	}

	if (ioctl(fd, UCCID_CMD_TXN_BEGIN, &begin) != 0) {
		err(EXIT_FAILURE, "failed to issue begin ioctl");
	}

	return (0);
}
