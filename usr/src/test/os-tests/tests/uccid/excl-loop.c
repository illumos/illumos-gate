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
 * Verify that we can grab a basic exclusive lock and then if we try to get
 * another lock it fails. Regardless of whether we do so through open(2) or
 * ioctl(2).
 */

#include <err.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <strings.h>
#include <unistd.h>
#include <errno.h>
#include <sys/debug.h>

#include <sys/usb/clients/ccid/uccid.h>

int
main(int argc, char *argv[])
{
	int fd, ret;
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

	if (ioctl(fd, UCCID_CMD_TXN_BEGIN, &begin) != 0) {
		err(EXIT_FAILURE, "failed to issue begin ioctl");
	}

	ret = ioctl(fd, UCCID_CMD_TXN_BEGIN, &begin);
	VERIFY3S(ret, ==, -1);
	VERIFY3S(errno, ==, EEXIST);

	if (ioctl(fd, UCCID_CMD_TXN_END, &end) != 0) {
		err(EXIT_FAILURE, "failed to issue end ioctl");
	}

	VERIFY0(close(fd));

	if ((fd = open(argv[1], O_RDWR)) < 0) {
		err(EXIT_FAILURE, "failed to open %s", argv[1]);
	}

	ret = ioctl(fd, UCCID_CMD_TXN_BEGIN, &begin);
	VERIFY0(ret);

	ret = ioctl(fd, UCCID_CMD_TXN_BEGIN, &begin);
	VERIFY3S(ret, ==, -1);
	VERIFY3S(errno, ==, EEXIST);

	VERIFY0(close(fd));

	return (0);
}
