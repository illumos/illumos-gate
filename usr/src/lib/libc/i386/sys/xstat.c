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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Wrapper functions to intercept calls to the obsolete
 * _xstat(), _lxstat(), _fxstat() and _xmknod() functions
 * and redirect them to the proper direct system calls.
 */

#include "lint.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>

int
_xstat(int version, const char *path, struct stat *statb)
{
	if (version != _STAT_VER) {
		errno = EINVAL;
		return (-1);
	}
	return (stat(path, statb));
}

int
_lxstat(int version, const char *path, struct stat *statb)
{
	if (version != _STAT_VER) {
		errno = EINVAL;
		return (-1);
	}
	return (lstat(path, statb));
}

int
_fxstat(int version, int fd, struct stat *statb)
{
	if (version != _STAT_VER) {
		errno = EINVAL;
		return (-1);
	}
	return (fstat(fd, statb));
}

int
_xmknod(int version, const char *path, mode_t mode, dev_t dev)
{
	if (version != _MKNOD_VER) {
		errno = EINVAL;
		return (-1);
	}
	return (mknod(path, mode, dev));
}
