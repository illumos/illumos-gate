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
 * Open a YubiKey class device read-only and try to get the basic information
 * applet through an APDU, which should fail. Try to get the status, which
 * should succeed, and attempt to power off, which should fail.
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
	int fd, ret;
	uccid_cmd_icc_modify_t uci;
	uccid_cmd_txn_begin_t begin;
	uccid_cmd_status_t ucs;
	uint8_t buf[UCCID_APDU_SIZE_MAX];

	if (argc != 2) {
		errx(EXIT_FAILURE, "missing required ccid path");
	}

	if ((fd = open(argv[1], O_RDONLY)) < 0) {
		err(EXIT_FAILURE, "failed to open %s", argv[1]);
	}

	bzero(&begin, sizeof (begin));
	begin.uct_version = UCCID_CURRENT_VERSION;
	if (ioctl(fd, UCCID_CMD_TXN_BEGIN, &begin) == 0) {
		errx(EXIT_FAILURE, "didn't fail to issue begin ioctl");
	}

	if ((ret = write(fd, yk_req, sizeof (yk_req))) != -1) {
		errx(EXIT_FAILURE, "didn't fail to write data");
	}

	if (errno != EBADF) {
		err(EXIT_FAILURE, "wrong errno for failed write, "
		    "expected EBADF");
	}

	if ((ret = read(fd, buf, sizeof (buf))) != -1) {
		errx(EXIT_FAILURE, "didn't fail to read data");
	}

	if (errno != EACCES) {
		err(EXIT_FAILURE, "wrong errno for failed read, "
		    "expected EACCES");
	}

	/* get card status */
	bzero(&ucs, sizeof (ucs));
	ucs.ucs_version = UCCID_CURRENT_VERSION;
	if ((ret = ioctl(fd, UCCID_CMD_STATUS, &ucs)) != 0) {
		err(EXIT_FAILURE, "failed to get status");
	}


	/* try to power off the card while opened read-only */
	bzero(&uci, sizeof (uci));
	uci.uci_version = UCCID_CURRENT_VERSION;
	uci.uci_action = UCCID_ICC_POWER_OFF;
	if ((ret = ioctl(fd, UCCID_CMD_ICC_MODIFY, &uci)) == 0) {
		errx(EXIT_FAILURE, "didn't fail to power off ICC");
	}

	if (errno != EBADF) {
		err(EXIT_FAILURE, "wrong errno for failed write, "
		    "expected EBADF");
	}

	return (0);
}
