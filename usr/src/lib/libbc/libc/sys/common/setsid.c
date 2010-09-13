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
 * Copyright 1993 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <errno.h>


static int setsid_called = 0;
static int real_setsid_called=0;
static int setsid_val, setsid_errno;


/* setpgrp system call number, setsid command code */
#define SYS_pgrpsys     39
#define SYS_setsid	3

int
setsid(void)
{
	if (setsid_called != getpid()) {
		setsid_called = getpid();
		return (bc_setsid());
	} else {
		errno = EPERM;
		return (-1);
	}
}
	


int
bc_setsid(void)
{
	if (real_setsid_called != getpid()) {
		real_setsid_called = getpid();
		setsid_val = _syscall(SYS_pgrpsys, SYS_setsid);
		setsid_errno = errno;
	}
	errno = setsid_errno;
	return (setsid_val);
}
