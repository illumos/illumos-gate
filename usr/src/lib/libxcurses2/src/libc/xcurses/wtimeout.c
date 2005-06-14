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
 * Copyright (c) 1995-1998, 2000 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/* LINTLIBRARY */

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
static char rcsID[] = "$Header: /rd/src/libc/xcurses/rcs/wtimeout.c 1.1 "
"1995/06/19 16:12:14 ant Exp $";
#endif
#endif

#include <private.h>

/*
 * Set blocking or non-blocking read for a specified window.
 * The delay is in milliseconds.
 */
void
wtimeout(WINDOW *w, int delay)
{
	if (delay < 0) {
		/* Blocking mode */
		w->_vmin = 1;
		w->_vtime = 0;
	} else {
		/* Non-Block (0 == delay) and delayed (0 < delay) */
		w->_vmin = 0;

		/*
		 * VTIME is in 1/10 of second
		 * w->_vtime value will be set to termios.c_cc[VMIN].
		 * Since c_cc[VMIN] is an unsigned char type, the value
		 * to be set needs to be smaller than or equal to 255.
		 * Also 'delay' is in milliseconds, so it is rounted up
		 * to the nearest 10th of a second.  Only when 'delay' is
		 * equal to 0, w->_vtime should become 0; otherwise,
		 * it should become a positive value.  The previous version
		 * of this code was using the expression "(delay + 50) /100",
		 * which was incorrect.
		 */
		w->_vtime = (delay > 25500) ? 255 : (delay + 99) / 100;
	}
}
