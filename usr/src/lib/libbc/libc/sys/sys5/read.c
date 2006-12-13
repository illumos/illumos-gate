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
#include <sys/types.h>
#include <unistd.h>
#include <sys/syscall.h>

/*
 * If reading from the utmp file, map the data to the SunOS 4.1
 * format on the fly.
 */

extern void to_utmp(char *, char *, int);

int
read(int fd, char *buf, int size)
{
	return (bc_read(fd, buf, size));
}

int
bc_read(int fd, char *buf, int size)
{
	int ret, off;
	char *nbuf;

	if (fd_get(fd) != -1) { /* we're reading utmp (utmpx, really) */
		size = getmodsize(size, sizeof (struct compat_utmp),
		    sizeof (struct utmpx));

		if ((nbuf = (void *)malloc(size)) == NULL) {
			(void) fprintf(stderr, "read: malloc failed\n");
			exit(-1);
		}

		if ((ret = _read(fd, nbuf, size)) == -1) {
			free(nbuf);
			return (-1);
		}

		to_utmp(buf, nbuf, ret);

		ret = getmodsize(ret, sizeof (struct utmpx),
		    sizeof (struct compat_utmp));
		free(nbuf);
		return (ret);
	}

	return (_read(fd, buf, size));
}

void
to_utmp(char *buf, char *nbuf, int len)
{
	struct compat_utmp *ut;
	struct utmpx *utx;

	utx = (struct utmpx *)nbuf;
	ut  = (struct compat_utmp *)buf;

	while ((char *)utx < (nbuf + len)) {
		(void) strncpy(ut->ut_line, utx->ut_line, sizeof (ut->ut_line));
		(void) strncpy(ut->ut_name, utx->ut_user, sizeof (ut->ut_name));
		(void) strncpy(ut->ut_host, utx->ut_host, sizeof (ut->ut_host));
		ut->ut_time = utx->ut_tv.tv_sec;
		utx++;
		ut++;
	}
}
