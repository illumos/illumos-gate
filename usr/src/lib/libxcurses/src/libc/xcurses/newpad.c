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
 * newpad.c
 * 
 * XCurses Library
 *
 * Copyright 1990, 1995 by Mortice Kern Systems Inc.  All rights reserved.
 *
 */

#if M_RCSID
#ifndef lint
static char rcsID[] = "$Header: /rd/src/libc/xcurses/rcs/newpad.c 1.1 1995/06/16 20:35:07 ant Exp $";
#endif
#endif

#include <private.h>

WINDOW *
(newpad)(nlines, ncols)
int nlines, ncols;
{
	WINDOW *w;

#ifdef M_CURSES_TRACE
	__m_trace("newpad(%d, %d)", nlines, ncols);
#endif

	w = __m_newwin((WINDOW *) 0, nlines, ncols, -1, -1);

	return __m_return_pointer("newpad", w);
}

WINDOW *
(subpad)(parent, nlines, ncols, begy, begx)
WINDOW *parent;
int nlines, ncols, begy, begx;
{
	WINDOW *w;

#ifdef M_CURSES_TRACE
	__m_trace(
		"subpad(%p, %d, %d, %d, %d)", 
		parent, nlines, ncols, begy, begx
	);
#endif

	w = subwin(parent, nlines, ncols, begy, begx);

	return __m_return_pointer("subpad", w);
}

