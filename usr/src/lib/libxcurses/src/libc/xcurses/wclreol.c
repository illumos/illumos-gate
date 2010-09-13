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
 * wclreol.c
 *
 * XCurses Library
 *
 * Copyright 1990, 1995 by Mortice Kern Inc.  All rights reserved.
 *
 */

#ifdef M_RCSID
#ifndef lint
static char rcsID[] = "$Header: /rd/src/libc/xcurses/rcs/wclreol.c 1.3 1995/06/21 20:30:58 ant Exp $";
#endif
#endif

#include <private.h>

/*f
 * Erase from the current cursor position in the window to the right 
 * margin.
 */
int
wclrtoeol(w)
WINDOW *w;
{
	int x;

#ifdef M_CURSES_TRACE
	__m_trace("wclrtoeol(%p) from (%d, %d)", w, w->_cury, w->_curx); 
#endif

	x = __m_cc_first(w, w->_cury, w->_curx);
	if (__m_cc_erase(w, w->_cury, x, w->_cury, w->_maxx-1) != 0)
		return __m_return_code("wclrtoeol", ERR);

	WSYNC(w);

	return __m_return_code("wclrtoeol", WFLUSH(w));
}
