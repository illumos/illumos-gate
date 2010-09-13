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
 * Copyright 1987 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/time.h>

/*
 * Backwards compatible utime.
 *
 * The System V system call allows any user with write permission
 * on a file to set the accessed and modified times to the current
 * time; they specify this by passing a null pointer to "utime".
 * This is done to simulate reading one byte from a file and
 * overwriting that byte with itself, which is the technique used
 * by older versions of the "touch" command.  The advantage of this
 * hack in the system call is that it works correctly even if the file
 * is zero-length.
 *
 * The BSD system call never allowed a null pointer so there should
 * be no compatibility problem there.
 */

int
utime(char *name, time_t otv[2])
{
	struct timeval tv[2];

	if (otv == 0) {
		return (utimes(name, (struct timeval *)0));
	} else {
		tv[0].tv_sec = (long)otv[0];
		tv[0].tv_usec = 0;
		tv[1].tv_sec = (long)otv[1];
		tv[1].tv_usec = 0;
	}
	return (utimes(name, tv));
}
