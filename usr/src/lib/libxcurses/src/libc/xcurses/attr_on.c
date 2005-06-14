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
 * attr_on.c
 *
 * Copyright 1990, 1995 by Mortice Kern Systems Inc.  All rights reserved.
 *
 */

#ifdef M_RCSID
#ifndef lint
static char rcsID[] = "$Header: /rd/src/libc/xcurses/rcs/attr_on.c 1.5 1995/07/10 16:09:09 ant Exp $";
#endif
#endif

#include <private.h>

int
(attr_on)(attr_t at, void *opts)
{
#ifdef M_CURSES_TRACE
        __m_trace("attr_on(%x, %p)", at, opts);
#endif

	stdscr->_fg._at |= at;

	return __m_return_code("attr_on", OK);
}

int
(attr_off)(attr_t at, void *opts)
{
#ifdef M_CURSES_TRACE
        __m_trace("attr_off(%x, %p)", at, opts);
#endif

	stdscr->_fg._at &= ~at;

	return __m_return_code("attr_off", OK);
}

int
(attr_set)(attr_t at, short co, void *opts)
{
#ifdef M_CURSES_TRACE
        __m_trace("attr_set(%x, %d, %p)", at, co, opts);
#endif

	stdscr->_fg._co = co;
	stdscr->_fg._at = at;

	return __m_return_code("attr_set", OK);
}

int
(color_set)(short co, void *opts)
{
#ifdef M_CURSES_TRACE
        __m_trace("color_set(%d, %p)", co, opts);
#endif

	stdscr->_fg._co = co;

	return __m_return_code("color_set", OK);
}

int
(attr_get)(attr_t *at, short *co, void *opts)
{
#ifdef M_CURSES_TRACE
        __m_trace("attr_get(%p, %p, %p)", at, co, opts);
#endif

	if (at != (attr_t *) 0)
		*at = stdscr->_fg._at;

	if (co != (short *) 0)
		*co = stdscr->_fg._co;

	return __m_return_int("attr_get", OK);
}

int
(standout)()
{
#ifdef M_CURSES_TRACE
        __m_trace("standout(void)");
#endif

	stdscr->_fg._at |= WA_STANDOUT;

	return __m_return_int("standout", 1);
}

int
(standend)()
{
#ifdef M_CURSES_TRACE
        __m_trace("standend(void)");
#endif

	stdscr->_fg._at = WA_NORMAL;

	return __m_return_int("standend", 1);
}

