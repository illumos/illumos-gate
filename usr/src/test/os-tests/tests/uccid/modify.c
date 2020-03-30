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
 * Verify that we can issue ICC_MODIFY ioctls. Also, check some of the failure
 * modes.
 */

#include <err.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <strings.h>
#include <unistd.h>
#include <sys/debug.h>
#include <errno.h>
#include <sys/mman.h>
#include <sys/param.h>

#include <sys/usb/clients/ccid/uccid.h>

static const uint8_t yk_req[] = {
	0x00, 0xa4, 0x04, 0x00, 0x07, 0xa0, 0x00, 0x00, 0x05, 0x27, 0x20, 0x01
};

int
main(int argc, char *argv[])
{
	int fd, ret;
	uccid_cmd_icc_modify_t uci;
	uccid_cmd_status_t ucs;
	uccid_cmd_txn_begin_t begin;
	uint8_t buf[UCCID_APDU_SIZE_MAX];

	if (argc != 2) {
		errx(EXIT_FAILURE, "missing required ccid path");
	}

	if ((fd = open(argv[1], O_RDWR)) < 0) {
		err(EXIT_FAILURE, "failed to open %s", argv[1]);
	}

	/* power off the card outside of a transaction */
	bzero(&uci, sizeof (uci));
	uci.uci_version = UCCID_CURRENT_VERSION;
	uci.uci_action = UCCID_ICC_POWER_OFF;
	ret = ioctl(fd, UCCID_CMD_ICC_MODIFY, &uci);
	VERIFY3S(ret, ==, 0);

	/* make sure the card is inactive now */
	bzero(&ucs, sizeof (ucs));
	ucs.ucs_version = UCCID_CURRENT_VERSION;
	ret = ioctl(fd, UCCID_CMD_STATUS, &ucs);
	VERIFY3S(ret, ==, 0);
	VERIFY3U(ucs.ucs_status & UCCID_STATUS_F_CARD_ACTIVE, ==, 0);

	/* power on the card outside of a transaction */
	bzero(&uci, sizeof (uci));
	uci.uci_version = UCCID_CURRENT_VERSION;
	uci.uci_action = UCCID_ICC_POWER_ON;
	ret = ioctl(fd, UCCID_CMD_ICC_MODIFY, &uci);
	VERIFY3S(ret, ==, 0);

	/* make sure the card is active again */
	bzero(&ucs, sizeof (ucs));
	ucs.ucs_version = UCCID_CURRENT_VERSION;
	ret = ioctl(fd, UCCID_CMD_STATUS, &ucs);
	VERIFY3S(ret, ==, 0);
	VERIFY3U(ucs.ucs_status & UCCID_STATUS_F_CARD_ACTIVE, !=, 0);


	/* enter transaction */
	bzero(&begin, sizeof (begin));
	begin.uct_version = UCCID_CURRENT_VERSION;
	if (ioctl(fd, UCCID_CMD_TXN_BEGIN, &begin) != 0) {
		err(EXIT_FAILURE, "failed to issue begin ioctl");
	}

	/* make sure the card is active (power on) */
	bzero(&ucs, sizeof (ucs));
	ucs.ucs_version = UCCID_CURRENT_VERSION;
	ret = ioctl(fd, UCCID_CMD_STATUS, &ucs);
	VERIFY3S(ret, ==, 0);
	VERIFY3U(ucs.ucs_status & UCCID_STATUS_F_CARD_ACTIVE, !=, 0);

	/* power off the card */
	bzero(&uci, sizeof (uci));
	uci.uci_version = UCCID_CURRENT_VERSION;
	uci.uci_action = UCCID_ICC_POWER_OFF;
	ret = ioctl(fd, UCCID_CMD_ICC_MODIFY, &uci);
	VERIFY3S(ret, ==, 0);

	/* make sure the card is inactive now */
	bzero(&ucs, sizeof (ucs));
	ucs.ucs_version = UCCID_CURRENT_VERSION;
	ret = ioctl(fd, UCCID_CMD_STATUS, &ucs);
	VERIFY3S(ret, ==, 0);
	VERIFY3U(ucs.ucs_status & UCCID_STATUS_F_CARD_ACTIVE, ==, 0);

	/* power on the card */
	bzero(&uci, sizeof (uci));
	uci.uci_version = UCCID_CURRENT_VERSION;
	uci.uci_action = UCCID_ICC_POWER_ON;
	ret = ioctl(fd, UCCID_CMD_ICC_MODIFY, &uci);
	VERIFY3S(ret, ==, 0);

	/* make sure the card is active again */
	bzero(&ucs, sizeof (ucs));
	ucs.ucs_version = UCCID_CURRENT_VERSION;
	ret = ioctl(fd, UCCID_CMD_STATUS, &ucs);
	VERIFY3S(ret, ==, 0);
	VERIFY3U(ucs.ucs_status & UCCID_STATUS_F_CARD_ACTIVE, !=, 0);

	/* do a warm reset of the card */
	bzero(&uci, sizeof (uci));
	uci.uci_version = UCCID_CURRENT_VERSION;
	uci.uci_action = UCCID_ICC_WARM_RESET;
	ret = ioctl(fd, UCCID_CMD_ICC_MODIFY, &uci);
	VERIFY3S(ret, ==, 0);

	/* make sure the card is still active */
	bzero(&ucs, sizeof (ucs));
	ucs.ucs_version = UCCID_CURRENT_VERSION;
	ret = ioctl(fd, UCCID_CMD_STATUS, &ucs);
	VERIFY3S(ret, ==, 0);
	VERIFY3U(ucs.ucs_status & UCCID_STATUS_F_CARD_ACTIVE, !=, 0);

	/* write a command to the card, which is assumed to be a YubiKey */
	if ((ret = write(fd, yk_req, sizeof (yk_req))) < 0) {
		err(EXIT_FAILURE, "failed to write data");
	}

	/* power off the card */
	bzero(&uci, sizeof (uci));
	uci.uci_version = UCCID_CURRENT_VERSION;
	uci.uci_action = UCCID_ICC_POWER_OFF;
	ret = ioctl(fd, UCCID_CMD_ICC_MODIFY, &uci);
	VERIFY3S(ret, ==, 0);

	/* make sure the card is inactive now */
	bzero(&ucs, sizeof (ucs));
	ucs.ucs_version = UCCID_CURRENT_VERSION;
	ret = ioctl(fd, UCCID_CMD_STATUS, &ucs);
	VERIFY3S(ret, ==, 0);
	VERIFY3U(ucs.ucs_status & UCCID_STATUS_F_CARD_ACTIVE, ==, 0);

	/* try to read the answer from the YubiKey. */
	ret = read(fd, buf, sizeof (buf));
	VERIFY3S(ret, ==, -1);
	VERIFY3S(errno, ==, ENXIO);

	/* power on the card */
	bzero(&uci, sizeof (uci));
	uci.uci_version = UCCID_CURRENT_VERSION;
	uci.uci_action = UCCID_ICC_POWER_ON;
	ret = ioctl(fd, UCCID_CMD_ICC_MODIFY, &uci);
	VERIFY3S(ret, ==, 0);

	/* make sure the card is active again */
	bzero(&ucs, sizeof (ucs));
	ucs.ucs_version = UCCID_CURRENT_VERSION;
	ret = ioctl(fd, UCCID_CMD_STATUS, &ucs);
	VERIFY3S(ret, ==, 0);
	VERIFY3U(ucs.ucs_status & UCCID_STATUS_F_CARD_ACTIVE, !=, 0);

	/* test various failure modes */
	uci.uci_version = UCCID_VERSION_ONE - 1;
	ret = ioctl(fd, UCCID_CMD_ICC_MODIFY, &uci);
	VERIFY3S(ret, ==, -1);
	VERIFY3S(errno, ==, EINVAL);

	uci.uci_version = UCCID_VERSION_ONE + 1;
	ret = ioctl(fd, UCCID_CMD_ICC_MODIFY, &uci);
	VERIFY3S(ret, ==, -1);
	VERIFY3S(errno, ==, EINVAL);

	uci.uci_version = UCCID_CURRENT_VERSION;
	uci.uci_action = 0;
	ret = ioctl(fd, UCCID_CMD_ICC_MODIFY, &uci);
	VERIFY3S(ret, ==, -1);
	VERIFY3S(errno, ==, EINVAL);

	uci.uci_version = UCCID_CURRENT_VERSION;
	uci.uci_action = -1;
	ret = ioctl(fd, UCCID_CMD_ICC_MODIFY, &uci);
	VERIFY3S(ret, ==, -1);
	VERIFY3S(errno, ==, EINVAL);

	return (0);
}
