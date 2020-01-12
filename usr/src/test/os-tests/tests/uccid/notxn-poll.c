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
 * Verify that trying to poll without a transaction / excl access works but
 * returns no events.
 */

#include <err.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/debug.h>
#include <fcntl.h>
#include <strings.h>
#include <unistd.h>
#include <errno.h>
#include <poll.h>

#include <sys/usb/clients/ccid/uccid.h>

int
main(int argc, char *argv[])
{
	int fd, ret;
	struct pollfd pfds[1];

	if (argc != 2) {
		errx(EXIT_FAILURE, "missing required ccid path");
	}

	if ((fd = open(argv[1], O_RDWR)) < 0) {
		err(EXIT_FAILURE, "failed to open %s", argv[1]);
	}

	pfds[0].fd = fd;
	pfds[0].events = POLLIN;
	pfds[0].revents = 0;

	ret = poll(pfds, 1, 0);
	VERIFY3S(ret, ==, 0);
	VERIFY3S(pfds[0].revents, ==, 0);

	return (0);
}
