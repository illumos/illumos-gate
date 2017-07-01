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
 * Verify that if we've grabbed an exclusive lock, another thread fails to grab
 * it as a non-blocking lock.
 */

#include <err.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <strings.h>
#include <unistd.h>
#include <sys/debug.h>
#include <thread.h>
#include <errno.h>

#include <sys/usb/clients/ccid/uccid.h>

void *
nonblock_thread(void *arg)
{
	uccid_cmd_txn_begin_t begin;
	int ret;
	int fd = (uintptr_t)arg;


	bzero(&begin, sizeof (begin));

	begin.uct_version = UCCID_CURRENT_VERSION;
	begin.uct_flags = UCCID_TXN_DONT_BLOCK;

	ret = ioctl(fd, UCCID_CMD_TXN_BEGIN, &begin);
	VERIFY3S(ret, ==, -1);
	VERIFY3S(errno, ==, EBUSY);

	return (NULL);
}

int
main(int argc, char *argv[])
{
	int fda, fdb;
	uccid_cmd_txn_begin_t begin;
	uccid_cmd_txn_end_t end;
	thread_t thr;

	if (argc != 2) {
		errx(EXIT_FAILURE, "missing required ccid path");
	}

	if ((fda = open(argv[1], O_RDWR)) < 0) {
		err(EXIT_FAILURE, "failed to open %s", argv[1]);
	}

	if ((fdb = open(argv[1], O_RDWR)) < 0) {
		err(EXIT_FAILURE, "failed to open %s", argv[1]);
	}

	bzero(&begin, sizeof (begin));
	bzero(&end, sizeof (end));

	begin.uct_version = UCCID_CURRENT_VERSION;
	end.uct_version = UCCID_CURRENT_VERSION;
	end.uct_flags = UCCID_TXN_END_RELEASE;

	if (ioctl(fda, UCCID_CMD_TXN_BEGIN, &begin) != 0) {
		err(EXIT_FAILURE, "failed to issue begin ioctl");
	}

	if (thr_create(NULL, 0, nonblock_thread, (void *)(uintptr_t)fdb, 0,
	    &thr) != 0) {
		err(EXIT_FAILURE, "failed to create thread");
	}

	if (thr_join(thr, NULL, NULL) != 0) {
		err(EXIT_FAILURE, "failed to join therad");
	}

	if (ioctl(fda, UCCID_CMD_TXN_END, &end) != 0) {
		err(EXIT_FAILURE, "failed to issue end ioctl");
	}

	return (0);
}
