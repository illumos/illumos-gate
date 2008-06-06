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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "lint.h"
#include <sys/types.h>
#include <errno.h>
#include <signal.h>
#include "libc.h"

/*
 * POSIX.1c version of the sigwait.
 * User gets it via static sigwait from header file.
 */
int
__posix_sigwait(const sigset_t *setp, int *signo)
{
	int nerrno = 0;
	int oerrno = errno;

	errno = 0;
	if ((*signo = sigwait((sigset_t *)setp)) == -1) {
		if (errno == 0)
			errno = EINVAL;
		else
			nerrno = errno;
	}
	errno = oerrno;
	return (nerrno);
}
