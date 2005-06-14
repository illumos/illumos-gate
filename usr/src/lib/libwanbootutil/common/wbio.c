/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "wbio.h"

/*
 * Write `buflen' bytes from `buffer' to the file represented by `fd'.
 * Returns -1 if all `buflen' bytes cannot be written, otherwise returns 0.
 */
int
wbio_nwrite(int fd, const void *buffer, size_t buflen)
{
	size_t		nwritten;
	ssize_t		nbytes;
	const char	*buf = buffer;

	for (nwritten = 0; nwritten < buflen; nwritten += nbytes) {
		nbytes = write(fd, &buf[nwritten], buflen - nwritten);
		if (nbytes <= 0)
			return (-1);
	}

	return (0);
}

/*
 * Read `buflen' bytes into `buffer' from the file represented by `fd'.
 * Returns -1 if all `buflen' bytes cannot be read, otherwise returns 0.
 */
int
wbio_nread(int fd, void *buffer, size_t buflen)
{
	size_t	nread;
	ssize_t	nbytes;
	char	*buf = buffer;

	for (nread = 0; nread < buflen; nread += nbytes) {
		nbytes = read(fd, &buf[nread], buflen - nread);
		if (nbytes <= 0)
			return (-1);
	}

	return (0);
}

/*
 * Read a random number of `buflen' bytes into `buffer' from /dev/urandom.
 * Returns -1 if all `buflen' bytes cannot be read, otherwise returns 0.
 */
int
wbio_nread_rand(void *buffer, size_t buflen)
{
	int fd;

	if ((fd = open("/dev/urandom", O_RDONLY)) == -1) {
		return (-1);
	}

	if (wbio_nread(fd, buffer, buflen) != 0) {
		(void) close(fd);
		return (-1);
	}

	(void) close(fd);
	return (0);
}
