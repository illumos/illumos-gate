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

/*
 * Check to see if a file descriptor is that of a stream.
 * Return 1 with errno set to 0 if it is. Otherwise,
 * return 0 with errno set to 0.
 * The only error returned is that case of a bad file desc.
 *
 */

#pragma weak _isastream = isastream

#include "lint.h"
#include <sys/types.h>
#include <stdio.h>
#include <errno.h>
#include <stropts.h>

int
isastream(int fd)
{
	int rval;

	rval = ioctl(fd, I_CANPUT, 0);
	if (rval == -1 && errno == EBADF)
		return (-1);

	errno = 0;
	if (rval == 0 || rval == 1)
		return (1);

	return (0);
}
