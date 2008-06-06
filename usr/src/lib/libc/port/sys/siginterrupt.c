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

int
siginterrupt(int sig, int flag)
{
	struct sigaction act;

	/*
	 * Check for valid signal number
	 */
	if (sig <= 0 || sig >= NSIG) {
		errno = EINVAL;
		return (-1);
	}

	(void) sigaction(sig, NULL, &act);
	if (flag)
		act.sa_flags &= ~SA_RESTART;
	else
		act.sa_flags |= SA_RESTART;
	return (sigaction(sig, &act, NULL));
}
