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
 * wchgat.c
 * 
 * XCurses Library
 *
 * Copyright 1990, 1995 by Mortice Kern Systems Inc.  All rights reserved.
 *
 */

#if M_RCSID
#ifndef lint
static char rcsID[] = "$Header: /rd/src/libc/xcurses/rcs/wchgat.c 1.3 1995/06/21 20:30:57 ant Exp $";
#endif
#endif

#include <private.h>

int
wchgat(WINDOW *w, int n, attr_t at, short co, const void *opts)
{
	int i, x;
	cchar_t *cp;

#ifdef M_CURSES_TRACE
	__m_trace("wchgat(%p, %d, %x, %d, %p)", w, n, at, co, opts);
#endif
	
	if (n < 0)
		n = w->_maxx;

	cp = &w->_line[w->_cury][w->_maxx];

	if (!cp->_f)
		return __m_return_code("wchgat", ERR);

	for (i = 0, x = w->_curx; x < w->_maxx; ++x, ++cp) {
		if (cp->_f && n <= i++)
			break;

		cp->_co = co;
		cp->_at = at; 
	}
		
	WSYNC(w);

	return __m_return_code("wchgat", WFLUSH(w));
}
