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

#include "chkpath.h"
#include <sys/syscall.h>
#include <unistd.h>
#include <errno.h>
#include <sys/fcntl.h>
#include <sys/param.h>

int
truncate(char *path, off_t length)
{
	int fd, ret = 0;

	CHKNULL(path);

	if (strcmp(path, "/etc/mtab") == 0 || strcmp(path, "/etc/fstab") == 0) {
		errno = ENOENT;
		return (-1);
	}
	if ((fd = open(path, O_WRONLY)) == -1) {
		return (-1);
	}

	if (ftruncate(fd, length) == -1) {
		close(fd);
		return (-1);
	}
	close(fd);
	return (0);
}
