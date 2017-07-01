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
 * Attempt to open a YubiKey class device and get the basic information applet
 * through an APDU.
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

static const uint8_t yk_req[] = {
	0x00, 0xa4, 0x04, 0x00, 0x07, 0xa0, 0x00, 0x00, 0x05, 0x27, 0x20, 0x01
};

int
main(int argc, char *argv[])
{
	int fd;
	ssize_t ret, i;
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

	if ((ret = write(fd, yk_req, sizeof (yk_req))) < 0) {
		err(EXIT_FAILURE, "failed to write data");
	}

	if ((ret = read(fd, buf, sizeof (buf))) < 0) {
		err(EXIT_FAILURE, "failed to read data");
	}

	(void) printf("read %d bytes\n", ret);
	for (i = 0; i < ret; i++) {
		(void) printf("%02x", buf[i]);
		if (i == (ret - 1) || (i % 16) == 15) {
			(void) printf("\n");
		} else {
			(void) printf(" ");
		}
	}

	return (0);
}
