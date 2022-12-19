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
 * Copyright 2022 Oxide Computer Company
 */

/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved   */

#pragma weak _isatty = isatty

#include "lint.h"
#include <sys/types.h>
#include <sys/termio.h>
#include <errno.h>
#include <unistd.h>

/*
 * Returns 1 iff file is a tty
 */
int
isatty(int f)
{
	struct termio tty;

	if (ioctl(f, TCGETA, &tty) < 0) {
		/*
		 * POSIX stipulates that systems may return an error here and if
		 * they do, it should either be EBADF or ENOTTY. In general, we
		 * assume that a driver that receives this ioctl is not going to
		 * return EBADF say due to an fd that's not open with the right
		 * mode and will instead return something else. It is possible
		 * to get many other errors here and we assume anything else
		 * that's returned means it's not a TTY and thus transform that.
		 *
		 * In the past, errno was preserved around this, which was
		 * incorrect because that meant that on failure there was no way
		 * to know whether it was meaningful or not. As pretty much
		 * every other system always returns an errno and there are
		 * consumers in the wild which assume they'll get something, we
		 * opt to always return an error.
		 */
		if (errno != EBADF) {
			errno = ENOTTY;
		}
		return (0);
	}
	return (1);
}
