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

#include "libaio.h"

void
_aiopanic(char *s)
{
	sigset_t sigmask;
	char buf[256];

	(void) snprintf(buf, sizeof (buf),
		"AIO PANIC (thread = %d): %s\n", thr_self(), s);
	(void) write(2, buf, strlen(buf));
	(void) sigset(SIGABRT, SIG_DFL);
	(void) sigemptyset(&sigmask);
	(void) sigaddset(&sigmask, SIGABRT);
	(void) sigprocmask(SIG_UNBLOCK, &sigmask, NULL);
	(void) thr_kill(thr_self(), SIGABRT);
	(void) kill(getpid(), SIGABRT);
	_exit(127);
}

int
assfail(char *a, char *f, int l)
{
	char buf[256];

	(void) snprintf(buf, sizeof (buf),
		"assertion failed: %s, file: %s, line:%d", a, f, l);
	_aiopanic(buf);
	return (0);
}
