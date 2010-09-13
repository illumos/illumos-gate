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
 *	Copyright (c) 1996 by Sun Microsystems, Inc.
 *
 * Map in a read-only page of zeroes at location zero, for stupid
 * programs that think a null pointer is as good as a null string.
 *
 * Use:
 *	LD_PRELOAD=0@0.so.1 program args ...
 *
 */
#pragma ident	"%Z%%M%	%I%	%E% SMI"

/* LINTLIBRARY */

#include <sys/types.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>

#pragma	init(__zero_at_zero)

void
__zero_at_zero()
{
	int fd;

	if ((fd = open("/dev/zero", O_RDWR)) < 0)
		return;
	(void) mmap(0, 1, PROT_READ, MAP_PRIVATE|MAP_FIXED, fd, 0);
	(void) close(fd);
}
