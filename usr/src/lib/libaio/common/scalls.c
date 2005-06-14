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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "libaio.h"

extern int __uaio_ok;
extern void _cancelon(void);
extern void _canceloff(void);

#pragma weak close = _libaio_close
int
_libaio_close(int fd)
{
	int	rc;

	if (__uaio_ok)
		(void) aiocancel_all(fd);

	_cancelon();
	rc = _close(fd);
	_canceloff();

	/*
	 * If the file is successfully closed, clear the
	 * bit for this file, as the next open may re-use this
	 * file descriptor, and the new file may have
	 * different kaio() behaviour
	 */
	if (rc == 0)
		CLEAR_KAIO_SUPPORTED(fd);

	return (rc);

}

#pragma weak fork = _libaio_fork
pid_t
_libaio_fork(void)
{
	pid_t pid;

	if (__uaio_ok || _kaio_ok) {
		pid = fork1();
		if (pid == 0)
			_aio_forkinit();
		return (pid);
	}
	return (_fork());
}
