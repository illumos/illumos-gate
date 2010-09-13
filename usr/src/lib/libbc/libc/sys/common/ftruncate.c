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

#include <sys/syscall.h>
#include <sys/types.h>

/* The following are from SVR4 sys/fcntl.h */

#define	F_FREESP	11	/* Free file space */
#define	F_WRLCK		02	/* Write Lock */

/* lock structure from SVR4. */
struct fl {
	short l_type;
	short l_whence;
	off_t l_start;
	off_t l_len;
	long  l_sysid;
	pid_t l_pid;
	long  pad[4];
};

int
ftruncate(int fd, off_t length)
{

	struct fl lck;

	lck.l_whence = 0;	/* offset l_start from beginning of file */
	lck.l_start = length;
	lck.l_type = F_WRLCK;	/* setting a write lock */
	lck.l_len = 0L;

	if (_syscall(SYS_fcntl, fd, F_FREESP, (int)&lck) == -1)
		return (-1);
	else
		return (0);
}
