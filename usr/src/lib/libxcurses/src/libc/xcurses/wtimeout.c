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
 * Copyright (c) 1995, by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * wtimeout.c
 *
 * XCurses Library
 *
 * Copyright 1990, 1994 by Mortice Kern Systems Inc.  All rights reserved.
 *
 */

#ifdef M_RCSID
#ifndef lint
static char rcsID[] = "$Header: /rd/src/libc/xcurses/rcs/wtimeout.c 1.1 1995/06/19 16:12:14 ant Exp $";
#endif
#endif

#include <private.h>

/*f
 * Set blocking or non-blocking read for a specified window.
 * The delay is in milliseconds.
 */
void
wtimeout(w, delay)
WINDOW *w;
int delay;
{
#ifdef M_CURSES_TRACE
	__m_trace("wtimeout(%p, %d)", w, delay);
#endif

	if (delay < 0) {
		/* Blocking mode */
		w->_vmin = 1;
		w->_vtime = 0;
	} else {
		/* Non-Block (0 == delay) and delayed (0 < delay) */
		w->_vmin = 0;

		/* VTIME is in 1/10 of second */
		w->_vtime = (delay+50)/100;	
	}

	__m_return_void("wtimeout");
}

