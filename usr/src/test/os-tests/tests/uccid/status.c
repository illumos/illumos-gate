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
 * Verify that we can issue various status ioctls regardless of whether or not
 * we have exclusive access on our handle. Also, check some of the failure
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

int
main(int argc, char *argv[])
{
	int fd, efd, ret;
	uccid_cmd_status_t ucs;
	uccid_cmd_txn_begin_t begin;
	void *badaddr;

	if (argc != 2) {
		errx(EXIT_FAILURE, "missing required ccid path");
	}

	if ((fd = open(argv[1], O_RDWR)) < 0) {
		err(EXIT_FAILURE, "failed to open %s", argv[1]);
	}

	if ((efd = open(argv[1], O_RDWR)) < 0) {
		err(EXIT_FAILURE, "failed to open %s", argv[1]);
	}

	bzero(&begin, sizeof (begin));
	begin.uct_version = UCCID_CURRENT_VERSION;
	if (ioctl(efd, UCCID_CMD_TXN_BEGIN, &begin) != 0) {
		err(EXIT_FAILURE, "failed to issue begin ioctl");
	}

	bzero(&ucs, sizeof (ucs));
	ucs.ucs_version = UCCID_CURRENT_VERSION;

	ret = ioctl(fd, UCCID_CMD_STATUS, &ucs);
	VERIFY3S(ret, ==, 0);

	ret = ioctl(efd, UCCID_CMD_STATUS, &ucs);
	VERIFY3S(ret, ==, 0);

	ucs.ucs_version = UCCID_VERSION_ONE - 1;
	ret = ioctl(efd, UCCID_CMD_STATUS, &ucs);
	VERIFY3S(ret, ==, -1);
	VERIFY3S(errno, ==, EINVAL);

	ucs.ucs_version = UCCID_VERSION_ONE + 1;
	ret = ioctl(efd, UCCID_CMD_STATUS, &ucs);
	VERIFY3S(ret, ==, -1);
	VERIFY3S(errno, ==, EINVAL);

	ucs.ucs_version = UCCID_VERSION_ONE - 1;
	ret = ioctl(fd, UCCID_CMD_STATUS, &ucs);
	VERIFY3S(ret, ==, -1);
	VERIFY3S(errno, ==, EINVAL);

	ucs.ucs_version = UCCID_VERSION_ONE + 1;
	ret = ioctl(fd, UCCID_CMD_STATUS, &ucs);
	VERIFY3S(ret, ==, -1);
	VERIFY3S(errno, ==, EINVAL);

	badaddr = mmap(NULL, PAGESIZE, PROT_READ, MAP_PRIVATE | MAP_ANON, -1,
	    0);
	VERIFY3P(badaddr, !=, MAP_FAILED);
	VERIFY0(munmap(badaddr, PAGESIZE));

	return (0);
}
