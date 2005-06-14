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
 * Copyright (c) 1995-1998 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/* LINTLIBRARY */

/*
 * intrflsh.c
 *
 * XCurses Library
 *
 * Copyright 1990, 1995 by Mortice Kern Systems Inc.  All rights reserved.
 *
 */

#if M_RCSID
#ifndef lint
static char rcsID[] =
"$Header: /team/ps/sun_xcurses/archive/local_changes/xcurses/src/lib/"
"libxcurses/src/libc/xcurses/rcs/intrflsh.c 1.3 1998/06/04 19:55:49 "
"cbates Exp $";
#endif
#endif

#include <private.h>

/*
 * When set, pressing an interrupt, suspend, or quiit key, the terminal's
 * output queue will be flushed.  Default inherited from the terminal
 * driver.  The window parameter is ignored.
 */
#undef intrflush

/* ARGSUSED */
int
intrflush(WINDOW *w, bool bf)
{
	PTERMIOS(_prog)->c_lflag &= ~NOFLSH;
	if (!bf)
		PTERMIOS(_prog)->c_lflag |= NOFLSH;

	return (__m_tty_set_prog_mode());
}
