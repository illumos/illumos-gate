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
 * Verify various bad read conditions fail successfully.
 */

#include <err.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <strings.h>
#include <unistd.h>
#include <errno.h>

#include <sys/usb/clients/ccid/uccid.h>

int
main(int argc, char *argv[])
{
	int fd;
	uccid_cmd_txn_begin_t begin;
	ssize_t ret;
	char buf[500];

	if (argc != 2) {
		errx(EXIT_FAILURE, "missing required ccid path");
	}

	if ((fd = open(argv[1], O_RDWR)) < 0) {
		err(EXIT_FAILURE, "failed to open %s", argv[1]);
	}

	bzero(&begin, sizeof (begin));
	begin.uct_version = UCCID_CURRENT_VERSION;

	/*
	 * Read without having a transaction
	 */
	ret = read(fd, buf, sizeof (buf));
	if (ret != -1) {
		errx(EXIT_FAILURE, "read succeeded when it should have failed "
		    "(EACCES case), returned %zd", ret);
	}

	if (errno != EACCES) {
		errx(EXIT_FAILURE, "found wrong value for errno. Expected "
		    "%d, received %d", EACCES, errno);
	}

	if (ioctl(fd, UCCID_CMD_TXN_BEGIN, &begin) != 0) {
		err(EXIT_FAILURE, "failed to issue begin ioctl");
	}

	ret = read(fd, buf, sizeof (buf));
	if (ret != -1) {
		errx(EXIT_FAILURE, "read succeeded when it should have failed "
		    "(ENODATA case), returned %zd", ret);
	}

	if (errno != ENODATA) {
		errx(EXIT_FAILURE, "found wrong value for errno. Expected "
		    "%d, received %d", ENODATA, errno);
	}

	return (0);
}
