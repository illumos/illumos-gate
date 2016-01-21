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
 * Copyright 2015 Joyent, Inc.  All rights reserved.
 */

#include <errno.h>
#include <unistd.h>
#include <sys/uio.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <alloca.h>
#include <string.h>
#include <sys/lx_syscall.h>
#include <sys/lx_misc.h>
#include <sys/lx_types.h>

long
lx_preadv(uintptr_t p1, uintptr_t p2, uintptr_t p3, uintptr_t p4)
{
	int 		fd = (int)p1;
	const struct iovec *iovp = (const struct iovec *)p2;
	int		cnt = (int)p3;
	off_t		off = (off_t)p4;
	ssize_t		ret;

	ret = preadv(fd, iovp, cnt, off);
	return (ret < 0 ? -errno : ret);
}

long
lx_pwritev(uintptr_t p1, uintptr_t p2, uintptr_t p3, uintptr_t p4)
{
	int 		fd = (int)p1;
	const struct iovec *iovp = (const struct iovec *)p2;
	int		cnt = (int)p3;
	off_t		off = (off_t)p4;
	ssize_t		ret;

	ret = pwritev(fd, iovp, cnt, off);
	return (ret < 0 ? -errno : ret);
}
