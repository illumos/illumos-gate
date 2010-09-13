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
 * wsyncup.c
 * 
 * XCurses Library
 *
 * Copyright 1990, 1995 by Mortice Kern Systems Inc.  All rights reserved.
 *
 */

#if M_RCSID
#ifndef lint
static char rcsID[] = "$Header: /rd/src/libc/xcurses/rcs/wsyncup.c 1.1 1995/06/21 20:04:28 ant Exp $";
#endif
#endif

#include <private.h>

int
syncok(WINDOW *w, bool bf)
{
#ifdef M_CURSES_TRACE
	__m_trace("syncok(%p, %d)", w, bf);
#endif

	w->_flags &= ~W_SYNC_UP;
	if (bf)
		w->_flags |= W_SYNC_UP;

	return __m_return_code("syncok", OK);
}

void
wsyncup(WINDOW *w)
{
	int y, py;
	WINDOW *p;

#ifdef M_CURSES_TRACE
	__m_trace("wsyncup(%p)", w);
#endif

	for (p = w->_parent; p != (WINDOW *) 0; w = p, p = w->_parent) {
		/* Update the parent's dirty region from the child's. */
		for (py = w->_begy - p->_begy, y = 0; y < w->_maxy; ++y, ++py) {
			if (0 <= w->_last[y]) {
				p->_first[py] = w->_begx + w->_first[y]; 
				p->_last[py] = w->_begx + w->_last[y]; 
			}
		}
	}

	__m_return_void("wsyncup");
}

void
wcursyncup(WINDOW *w)
{
	int y, py;
	WINDOW *p;

#ifdef M_CURSES_TRACE
	__m_trace("wcursyncup(%p)", w);
#endif

	for (p = w->_parent; p != (WINDOW *) 0; w = p, p = w->_parent) {
		p->_cury = w->_begy + w->_cury;
		p->_curx = w->_begx + w->_curx;
	}

	__m_return_void("wcursyncup");
}

