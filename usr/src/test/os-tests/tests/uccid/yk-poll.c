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
 * Open a YubiKey class device and get the basic information applet
 * through an APDU while using poll(2) to check device readyness.
 */

#include <err.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <strings.h>
#include <unistd.h>
#include <errno.h>
#include <poll.h>

#include <sys/usb/clients/ccid/uccid.h>

static const uint8_t yk_req[] = {
	0x00, 0xa4, 0x04, 0x00, 0x07, 0xa0, 0x00, 0x00, 0x05, 0x27, 0x20, 0x01
};

int
main(int argc, char *argv[])
{
	int fd, ret;
	struct pollfd pfds[1];
	uccid_cmd_txn_begin_t begin;
	uint8_t buf[UCCID_APDU_SIZE_MAX];

	if (argc != 2) {
		errx(EXIT_FAILURE, "missing required ccid path");
	}

	if ((fd = open(argv[1], O_RDWR)) < 0) {
		err(EXIT_FAILURE, "failed to open %s", argv[1]);
	}

	bzero(&begin, sizeof (begin));
	begin.uct_version = UCCID_CURRENT_VERSION;
	if (ioctl(fd, UCCID_CMD_TXN_BEGIN, &begin) != 0) {
		err(EXIT_FAILURE, "failed to issue begin ioctl");
	}

	pfds[0].fd = fd;
	pfds[0].events = POLLOUT | POLLIN | POLLRDNORM;
	pfds[0].revents = 0;

	ret = poll(pfds, 1, 0);
	if (ret != 1) {
		err(EXIT_FAILURE, "poll didn't return 1, returned %d "
		    "(errno %d)", ret, errno);
	}

	if ((pfds[0].revents & POLLOUT) != POLLOUT) {
		err(EXIT_FAILURE, "expecting pollout, got %d", pfds[0].revents);
	}

	if ((ret = write(fd, yk_req, sizeof (yk_req))) < 0) {
		err(EXIT_FAILURE, "failed to write data");
	}

	pfds[0].revents = 0;

	ret = poll(pfds, 1, -1);
	if (ret != 1) {
		err(EXIT_FAILURE, "poll didn't return 1, returned %d "
		    "(errno %d)", ret, errno);
	}

	if ((pfds[0].revents & (POLLIN | POLLRDNORM)) !=
	    (POLLIN | POLLRDNORM)) {
		err(EXIT_FAILURE, "expecting pollin|pollrdnorm, got %d",
		    pfds[0].revents);
	}

	if ((ret = read(fd, buf, sizeof (buf))) < 0) {
		err(EXIT_FAILURE, "failed to read data");
	}

	pfds[0].revents = 0;

	ret = poll(pfds, 1, 0);
	if (ret != 1) {
		err(EXIT_FAILURE, "poll didn't return 1, returned %d "
		    "(errno %d)", ret, errno);
	}

	if ((pfds[0].revents & POLLOUT) != POLLOUT) {
		err(EXIT_FAILURE, "expecting pollout, got %d", pfds[0].revents);
	}

	return (0);
}
