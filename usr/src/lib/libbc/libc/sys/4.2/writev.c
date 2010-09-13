/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "../common/compat.h"
#include <stdio.h>
#include <sys/errno.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/uio.h>

/*
 * If writing to a utmp-like file, map the utmp structure to
 * new format on the fly.
 */
extern int errno;

extern int conv2utmpx(char *, char *, int);

int
writev(int fd, struct iovec *iov, int iovcnt)
{
	return (bc_writev(fd, iov, iovcnt));
}

int
bc_writev(int fd, struct iovec *iov, int iovcnt)
{
	int ret, off;
	int nsize, total = 0;
	char *nbuf;
	int i;

	if (fd_get(fd) != -1) { /* writing utmp (utmpx, actually) */
		for (i = 0; i < iovcnt; i++) {
			nsize = getmodsize(iov[i].iov_len,
			    sizeof (struct compat_utmp),
			    sizeof (struct utmpx));

			if ((nbuf = (void *)malloc(nsize)) == NULL) {
				fprintf(stderr, "writev: malloc failed\n");
				exit(-1);
			}

			(void) memset(nbuf, 0, nsize);

			ret = conv2utmpx(nbuf, iov[i].iov_base, iov[i].iov_len);

			if ((ret = _write(fd, nbuf, ret)) == -1) {
				if (errno == EAGAIN)
					errno = EWOULDBLOCK;
				free(nbuf);
				return (-1);
			}

			free(nbuf);

			ret = getmodsize(ret, sizeof (struct utmpx),
			    sizeof (struct compat_utmp));
			total += ret;
		}
		return (total);
	}

	if ((ret = _writev(fd, iov, iovcnt)) == -1) {
		if (errno == EAGAIN)
			errno = EWOULDBLOCK;
	}

	return (ret);
}
