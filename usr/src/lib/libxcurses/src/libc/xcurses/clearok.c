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
 * clearok.c
 * 
 * XCurses Library
 *
 * Copyright 1990, 1995 by Mortice Kern Systems Inc.  All rights reserved.
 *
 */

#if M_RCSID
#ifndef lint
static char rcsID[] = "$Header: /rd/src/libc/xcurses/rcs/clearok.c 1.3 1995/06/19 16:12:07 ant Exp $";
#endif
#endif

#include <private.h>

int
clearok(WINDOW *w, bool bf)
{
#ifdef M_CURSES_TRACE
	__m_trace("clearok(%p, %d)", w, bf);
#endif

	w->_flags &= ~W_CLEAR_WINDOW;
	if (bf)
		w->_flags |= W_CLEAR_WINDOW;

	return __m_return_code("clearok", OK);
}

void
immedok(WINDOW *w, bool bf)
{
#ifdef M_CURSES_TRACE
	__m_trace("immedok(%p, %d)", w, bf);
#endif

	w->_flags &= ~W_FLUSH;
	if (bf)
		w->_flags |= W_FLUSH;

	__m_return_void("immedok");
}

int
leaveok(WINDOW *w, bool bf)
{
#ifdef M_CURSES_TRACE
	__m_trace("leaveok(%p, %d)", w, bf);
#endif

	w->_flags &= ~W_LEAVE_CURSOR;
	if (bf)
		w->_flags |= W_LEAVE_CURSOR;

	return __m_return_code("leaveok", OK);
}

int
notimeout(WINDOW *w, bool bf)
{
#ifdef M_CURSES_TRACE
	__m_trace("notimeout(%p, %d)", w, bf);
#endif

	w->_flags &= ~W_USE_TIMEOUT;
	if (!bf)
		w->_flags |= W_USE_TIMEOUT;

	return __m_return_code("notimeout", OK);
}

int
scrollok(WINDOW *w, bool bf)
{
#ifdef M_CURSES_TRACE
	__m_trace("scrollok(%p, %d)", w, bf);
#endif

	w->_flags &= ~W_CAN_SCROLL;
	if (bf)
		w->_flags |= W_CAN_SCROLL;

	return __m_return_code("scrollok", OK);
}

