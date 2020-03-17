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
 * Copyright 2020 Joyent, Inc.
 */

/*
 * Some simple testing of the read/writev() family: specifically we're checking
 * IOV_MAX == 1024, and that a large-file compiled 32-bit binary can correctly
 * access certain offsets.
 */

#include <sys/uio.h>
#include <strings.h>
#include <limits.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <err.h>

#define	ONE_GIG ((off_t)1024 * 1024 * 1024)

#define	DATA_LEN (sizeof ("data"))

char path[] = "/var/tmp/writev_test.XXXXXX";

static void
cleanup(void)
{
	(void) unlink(path);
}

int
main(int argc, char *argv[])
{
	char data[(IOV_MAX + 1) * DATA_LEN] = "";
	struct iovec iov[IOV_MAX + 1];

	if (IOV_MAX != 1024)
		errx(EXIT_FAILURE, "IOV_MAX != 1024");

	int fd = mkstemp(path);

	if (fd == -1)
		err(EXIT_FAILURE, "failed to create file");

	(void) atexit(cleanup);

	int ret = ftruncate(fd, ONE_GIG * 8);

	if (ret != 0)
		err(EXIT_FAILURE, "failed to truncate file");

	for (int i = 0; i < IOV_MAX + 1; i++) {
		(void) strcpy(data + i * DATA_LEN, "data");
		iov[i].iov_base = data + i * 5;
		iov[i].iov_len = DATA_LEN;
	}

	ssize_t written = writev(fd, iov, IOV_MAX + 1);

	if (written != -1 || errno != EINVAL)
		errx(EXIT_FAILURE, "writev(IOV_MAX + 1) didn't fail properly");

	written = writev(fd, iov, IOV_MAX);

	if (written == -1)
		err(EXIT_FAILURE, "writev failed");

	bzero(data, sizeof (data));

	ssize_t read = preadv(fd, iov, IOV_MAX, 0);

	if (read != DATA_LEN * IOV_MAX)
		err(EXIT_FAILURE, "preadv failed");

	for (int i = 0; i < IOV_MAX; i++) {
		if (strcmp(data + i * DATA_LEN, "data") != 0)
			errx(EXIT_FAILURE, "bad read at 0x%lx", i * DATA_LEN);
	}

	/*
	 * Now test various "interesting" offsets.
	 */

	for (off_t off = 0; off < ONE_GIG * 8; off += ONE_GIG) {
		if ((written = pwritev(fd, iov, 1, off)) != DATA_LEN)
			err(EXIT_FAILURE, "pwritev(0x%lx) failed", off);
	}

	for (off_t off = 0; off < ONE_GIG * 8; off += ONE_GIG) {
		if ((read = preadv(fd, iov, 1, off)) != DATA_LEN)
			err(EXIT_FAILURE, "preadv(0x%lx) failed", off);
		if (strcmp(data, "data") != 0)
			errx(EXIT_FAILURE, "bad read at 0x%lx", off);
	}

	return (EXIT_SUCCESS);
}
