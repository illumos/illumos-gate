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

#include "lint.h"
#include "file64.h"
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include "stdiom.h"

static int pass = 0;	/* counts how many times abort has been called */

/*
 * abort() - terminate current process with dump via SIGABRT
 */
void
abort(void)
{
	sigset_t	set;
	struct sigaction	act;

	if (!sigaction(SIGABRT, NULL, &act) &&
	    act.sa_handler != SIG_DFL && act.sa_handler != SIG_IGN) {
		/*
		 * User handler is installed, invokes user handler before
		 * taking default action.
		 *
		 * Send SIGABRT, unblock SIGABRT if blocked.
		 * If there is pending signal SIGABRT, we only need to unblock
		 * SIGABRT.
		 */
		if (!sigprocmask(SIG_SETMASK, NULL, &set) &&
		    sigismember(&set, SIGABRT)) {
			if (!sigpending(&set) && !sigismember(&set, SIGABRT))
				(void) raise(SIGABRT);
			(void) sigrelse(SIGABRT);
		} else
			(void) raise(SIGABRT);
	}

	if (++pass == 1)
		__cleanup();

	for (;;) {
		(void) signal(SIGABRT, SIG_DFL);
		(void) sigrelse(SIGABRT);
		(void) raise(SIGABRT);
	}
}
