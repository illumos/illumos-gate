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

#pragma weak _tcsetattr = tcsetattr

#include "lint.h"
#include <sys/types.h>
#include <sys/termios.h>
#include <errno.h>
#include <unistd.h>

/*
 * set parameters associated with termios
 */

int
tcsetattr(int fildes, int optional_actions, const struct termios *termios_p)
{

	int rval;

	switch (optional_actions) {

		case TCSANOW:

			rval = ioctl(fildes, TCSETS, termios_p);
			break;

		case TCSADRAIN:

			rval = ioctl(fildes, TCSETSW, termios_p);
			break;

		case TCSAFLUSH:

			rval = ioctl(fildes, TCSETSF, termios_p);
			break;

		default:

			rval = -1;
			errno = EINVAL;
	}
	return (rval);
}
