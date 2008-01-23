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

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved	*/

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "synonyms.h"
#include <sys/param.h>
#include <sys/sockio.h>
#include <sys/filio.h>
#include <sys/file.h>
#include <sys/types.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/stropts.h>
#include <sys/socket.h>
#include <sys/stropts.h>
#include <sys/stream.h>
#include <sys/socketvar.h>
#include <sys/syscall.h>
#include <errno.h>
#include <stdio.h>
#include <stdarg.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include "libc.h"

/*
 * We must be careful to call only functions that are private
 * to libc here, to avoid invoking the dynamic linker.
 * This is important because _private_fcntl() is called from
 * posix_spawn() after vfork() and we must never invoke the
 * dynamic linker in a vfork() child.
 */

extern int _private_ioctl(int, int, ...);
extern int __fcntl_syscall(int fd, int cmd, ...);

#if !defined(_LP64)
/*
 * XXX these hacks are needed for X.25 which assumes that s_fcntl and
 * s_ioctl exist in the socket library.
 * There is no need for _s_ioctl for other purposes.
 */
#pragma weak s_fcntl = __fcntl
#pragma weak _s_fcntl = __fcntl
#pragma weak s_ioctl = _s_ioctl
int
_s_ioctl(int fd, int cmd, intptr_t arg)
{
	return (_private_ioctl(fd, cmd, arg));
}
#endif	/* _LP64 */

#pragma weak _private_fcntl = __fcntl
int
__fcntl(int fd, int cmd, ...)
{
	int	res;
	int	pid;
	intptr_t arg;
	va_list ap;

	va_start(ap, cmd);
	arg = va_arg(ap, intptr_t);
	va_end(ap);

	switch (cmd) {
	case F_SETOWN:
		pid = (int)arg;
		return (_private_ioctl(fd, FIOSETOWN, &pid));

	case F_GETOWN:
		if (_private_ioctl(fd, FIOGETOWN, &res) < 0)
			return (-1);
		return (res);

	default:
		return (__fcntl_syscall(fd, cmd, arg));
	}
}
