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
 * wattr_on.c
 *
 * Copyright 1990, 1995 by Mortice Kern Systems Inc.  All rights reserved.
 *
 */

#ifdef M_RCSID
#ifndef lint
static char rcsID[] = "$Header: /rd/src/libc/xcurses/rcs/wattr_on.c 1.3 1995/06/05 18:55:16 ant Exp $";
#endif
#endif

#include <private.h>

#undef wattr_on

int
wattr_on(WINDOW *w, attr_t at, void *opts)
{
#ifdef M_CURSES_TRACE
        __m_trace("wattr_on(%p, %x, %p)", w, at, opts);
#endif

	w->_fg._at |= at;

	return __m_return_code("wattr_on", OK);
}

#undef wattr_off

int
wattr_off(WINDOW *w, attr_t at, void *opts)
{
#ifdef M_CURSES_TRACE
        __m_trace("wattr_off(%p, %x, %p)", w, at, opts);
#endif

	w->_fg._at &= ~at;

	return __m_return_code("wattr_off", OK);
}

#undef wattr_set

int
wattr_set(WINDOW *w, attr_t at, short co, void *opts)
{
#ifdef M_CURSES_TRACE
        __m_trace("wattr_set(%p, %x, %d, %p)", w, at, co, opts);
#endif

	w->_fg._co = co;
	w->_fg._at = at;

	return __m_return_code("wattr_set", OK);
}

#undef wattr_get

int
wattr_get(WINDOW *w, attr_t *at, short *co, void *opts)
{
#ifdef M_CURSES_TRACE
        __m_trace("wattr_get(%p, %p, %p, %p)", w, at, co, opts);
#endif

	if (at != (attr_t *) 0)
		*at = w->_fg._at;

	if (co != (short *) 0)
		*co = w->_fg._co;

	return __m_return_int("wattr_get", OK);
}

#undef wcolor_set

int
wcolor_set(WINDOW *w, short co, void *opts)
{
#ifdef M_CURSES_TRACE
        __m_trace("wcolor_set(%p, %d, %p)", w, co, opts);
#endif

	w->_fg._co = co;

	return __m_return_code("wcolor_set", OK);
}

#undef wstandout

int
wstandout(WINDOW *w)
{
#ifdef M_CURSES_TRACE
        __m_trace("wstandout(%p)", w);
#endif

	w->_fg._at |= WA_STANDOUT;

	return __m_return_int("wstandout", 1);
}

#undef wstandend

int
wstandend(WINDOW *w)
{
#ifdef M_CURSES_TRACE
        __m_trace("wstandend(%p)", w);
#endif

	w->_fg._at = WA_NORMAL;

	return __m_return_int("wstandend", 1);
}

