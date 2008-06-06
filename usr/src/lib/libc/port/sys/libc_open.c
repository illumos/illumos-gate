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

/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved  	*/

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "lint.h"
#include <sys/mkdev.h>
#include <limits.h>
#include <stdarg.h>
#include <unistd.h>
#include <strings.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/stropts.h>
#include <sys/stream.h>
#include <sys/ptms.h>
#include "libc.h"

#if !defined(_LP64)
extern int __open64_syscall(const char *fname, int oflag, mode_t mode);
#endif

extern int __open_syscall(const char *fname, int oflag, mode_t mode);

static void push_module(int fd);
static int isptsfd(int fd);
static void itoa(int i, char *ptr);

int
__open(const char *fname, int oflag, ...)
{
	mode_t mode;
	int fd;
	va_list ap;

	va_start(ap, oflag);
	mode = va_arg(ap, mode_t);
	va_end(ap);

	/*
	 * XPG4v2 requires that open of a slave pseudo terminal device
	 * provides the process with an interface that is identical to
	 * the terminal interface. For a more detailed discussion,
	 * see bugid 4025044.
	 */
	fd = __open_syscall(fname, oflag, mode);
	if (libc__xpg4 != 0 && fd >= 0 && isptsfd(fd))
		push_module(fd);
	return (fd);
}

#if !defined(_LP64)
/*
 * The 32-bit APIs to large files require this interposition.
 * The 64-bit APIs just fall back to __open() above.
 */
int
__open64(const char *fname, int oflag, ...)
{
	mode_t mode;
	int fd;
	va_list ap;

	va_start(ap, oflag);
	mode = va_arg(ap, mode_t);
	va_end(ap);

	/*
	 * XPG4v2 requires that open of a slave pseudo terminal device
	 * provides the process with an interface that is identical to
	 * the terminal interface. For a more detailed discussion,
	 * see bugid 4025044.
	 */
	fd = __open64_syscall(fname, oflag, mode);
	if (libc__xpg4 != 0 && fd >= 0 && isptsfd(fd))
		push_module(fd);
	return (fd);
}
#endif	/* !_LP64 */

/*
 * Check if the file matches an entry in the /dev/pts directory.
 * Be careful to preserve errno.
 */
static int
isptsfd(int fd)
{
	char buf[TTYNAME_MAX];
	char *str1 = buf;
	const char *str2 = "/dev/pts/";
	struct stat64 fsb, stb;
	int oerrno = errno;
	int rval = 0;

	if (fstat64(fd, &fsb) == 0 && S_ISCHR(fsb.st_mode)) {
		/*
		 * Do this without strcpy() or strlen(),
		 * to avoid invoking the dynamic linker.
		 */
		while (*str2 != '\0')
			*str1++ = *str2++;
		/*
		 * Inline version of minor(dev), to avoid the dynamic linker.
		 */
		itoa(fsb.st_rdev & MAXMIN, str1);
		if (stat64(buf, &stb) == 0)
			rval = (stb.st_rdev == fsb.st_rdev);
	}
	errno = oerrno;
	return (rval);
}

/*
 * Converts a number to a string (null terminated).
 */
static void
itoa(int i, char *ptr)
{
	int dig = 0;
	int tempi;

	tempi = i;
	do {
		dig++;
		tempi /= 10;
	} while (tempi);

	ptr += dig;
	*ptr = '\0';
	while (--dig >= 0) {
		*(--ptr) = i % 10 + '0';
		i /= 10;
	}
}

/*
 * Push modules to provide tty semantics
 */
static void
push_module(int fd)
{
	struct strioctl istr;
	int oerrno = errno;

	istr.ic_cmd = PTSSTTY;
	istr.ic_len = 0;
	istr.ic_timout = 0;
	istr.ic_dp = NULL;
	if (ioctl(fd, I_STR, &istr) != -1) {
		(void) ioctl(fd, __I_PUSH_NOCTTY, "ptem");
		(void) ioctl(fd, __I_PUSH_NOCTTY, "ldterm");
		(void) ioctl(fd, __I_PUSH_NOCTTY, "ttcompat");
		istr.ic_cmd = PTSSTTY;
		istr.ic_len = 0;
		istr.ic_timout = 0;
		istr.ic_dp = NULL;
		(void) ioctl(fd, I_STR, &istr);
	}
	errno = oerrno;
}
