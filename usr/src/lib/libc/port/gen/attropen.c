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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 *	attropen -- C library extension routine
 */

#if !defined(_LP64) && _FILE_OFFSET_BITS == 64
#pragma weak _attropen64 = attropen64
#else
#pragma weak _attropen = attropen
#endif

#include "lint.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <stdarg.h>

#if !defined(_LP64) && _FILE_OFFSET_BITS == 64

int
attropen64(const char *file, const char *attr, int oflag, ...)
{
	int fd;
	int attrfd;
	int saverrno;
	va_list ap;

	va_start(ap, oflag);

	if ((fd = open64(file, O_RDONLY|O_NONBLOCK)) == -1) {
		va_end(ap);
		return (-1);
	}

	if ((attrfd = openat64(fd, attr, oflag | O_XATTR,
	    va_arg(ap, mode_t))) == -1) {
		saverrno = errno;
		(void) close(fd);
		errno = saverrno;
		va_end(ap);
		return (-1);
	}

	(void) close(fd);
	va_end(ap);
	return (attrfd);
}

#else

int
attropen(const char *file, const char *attr, int oflag, ...)
{
	int fd;
	int attrfd;
	int saverrno;
	va_list ap;

	va_start(ap, oflag);

	if ((fd = open(file, O_RDONLY|O_NONBLOCK)) == -1) {
		va_end(ap);
		return (-1);
	}

	if ((attrfd = openat(fd, attr, oflag | O_XATTR,
	    va_arg(ap, mode_t))) == -1) {
		saverrno = errno;
		(void) close(fd);
		errno = saverrno;
		va_end(ap);
		return (-1);
	}

	(void) close(fd);
	va_end(ap);
	return (attrfd);
}

#endif /* _FILE_OFFSET_BITS == 64 */
