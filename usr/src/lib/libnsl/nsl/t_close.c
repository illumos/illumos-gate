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

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.5 */

#include "mt.h"
#include <errno.h>
#include <unistd.h>
#include <xti.h>
#include <signal.h>
#include <stropts.h>
#include "tx.h"

int
_tx_close(int fd, int api_semantics)
{
	sigset_t mask;
	int sv_errno;

	if (_t_checkfd(fd, 0, api_semantics) == NULL)
		return (-1);

	(void) thr_sigsetmask(SIG_SETMASK, &fillset, &mask);
	sig_mutex_lock(&_ti_userlock);
	if (_t_delete_tilink(fd) < 0) {
		sv_errno = errno;
		sig_mutex_unlock(&_ti_userlock);
		(void) thr_sigsetmask(SIG_SETMASK, &mask, NULL);
		errno = sv_errno;
		return (-1);
	}
	/*
	 * Note: close() needs to be inside the lock. If done
	 * outside, another process may inherit the desriptor
	 * and recreate library level instance structures
	 */
	(void) close(fd);

	sig_mutex_unlock(&_ti_userlock);
	(void) thr_sigsetmask(SIG_SETMASK, &mask, NULL);
	return (0);
}
