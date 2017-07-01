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
 * Verify that we can grab a basic exclusive lock through an ioctl on the slot.
 * Then that we can release it afterwards.
 */

#include <err.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <strings.h>
#include <unistd.h>

#include <sys/usb/clients/ccid/uccid.h>

int
main(int argc, char *argv[])
{
	int fd;
	uint_t i;
	uccid_cmd_txn_begin_t begin;
	uccid_cmd_txn_end_t end;

	if (argc != 2) {
		errx(EXIT_FAILURE, "missing required ccid path");
	}

	if ((fd = open(argv[1], O_RDWR)) < 0) {
		err(EXIT_FAILURE, "failed to open %s", argv[1]);
	}

	bzero(&begin, sizeof (begin));
	bzero(&end, sizeof (end));

	begin.uct_version = UCCID_CURRENT_VERSION;
	end.uct_version = UCCID_CURRENT_VERSION;
	end.uct_flags = UCCID_TXN_END_RELEASE;

	for (i = 0; i < 10; i++) {
		if (ioctl(fd, UCCID_CMD_TXN_BEGIN, &begin) != 0) {
			err(EXIT_FAILURE, "failed to issue begin ioctl");
		}

		if (ioctl(fd, UCCID_CMD_TXN_END, &end) != 0) {
			err(EXIT_FAILURE, "failed to issue end ioctl");
		}
	}

	return (0);
}
