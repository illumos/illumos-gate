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
 * Copyright 2024 Oxide Computer Company
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved	*/

#include "lint.h"
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

#if !defined(_LP64)
/*
 * XXX these hacks are needed for X.25 which assumes that s_fcntl and
 * s_ioctl exist in the socket library.
 * There is no need for s_ioctl for other purposes.
 */
#pragma weak s_fcntl = __fcntl
#pragma weak _s_fcntl = __fcntl
int
s_ioctl(int fd, int cmd, intptr_t arg)
{
	return (ioctl(fd, cmd, arg));
}
#endif	/* _LP64 */

int
__fcntl(int fd, int cmd, ...)
{
	int	res;
	int	pid;
	intptr_t arg, arg1 = 0;
	va_list ap;

	/*
	 * The fcntl(2) entry points are responsible for marshalling arguments
	 * into intptr_t sized objects prior to calling this. The kernel only
	 * works in terms of intptr_t sized arguments; however, some calls (like
	 * F_DUP3FD) are in terms of two int sized arguments.
	 */
	va_start(ap, cmd);
	arg = va_arg(ap, intptr_t);
	if (cmd == F_DUP3FD) {
		arg1 = va_arg(ap, intptr_t);
	}
	va_end(ap);

	switch (cmd) {
	case F_SETOWN:
		pid = (int)arg;
		return (ioctl(fd, FIOSETOWN, &pid));

	case F_GETOWN:
		if (ioctl(fd, FIOGETOWN, &res) < 0)
			return (-1);
		return (res);

	default:
		return (syscall(SYS_fcntl, fd, cmd, arg, arg1));
	}
}
