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
 * Copyright (c) 1999 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "compat.h"
#include <errno.h>
#include <syscall.h>
#include <sys/types.h>
#include <unistd.h>

extern int errno;

off_t lseek(int fd, off_t offset, int whence)
{
	int off, ret;

	if (whence < 0 || whence > 2) {
		errno = EINVAL;
		return (-1);
	}
	if (fd_get(fd) != -1) {
		off = getmodsize(offset, sizeof(struct utmpx), 
						sizeof(struct compat_utmp));
		if ((ret = _syscall(SYS_lseek, fd, off, whence)) == -1)
			return(-1);

		ret = getmodsize(ret, sizeof(struct compat_utmp),
					sizeof(struct utmpx));
		return (ret);
	}
	else 
		return (_syscall(SYS_lseek, fd, offset, whence));
}
