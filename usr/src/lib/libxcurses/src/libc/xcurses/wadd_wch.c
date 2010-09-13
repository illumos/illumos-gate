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
 * wadd_wch.c
 * 
 * XCurses Library
 *
 * Copyright 1990, 1995 by Mortice Kern Systems Inc.  All rights reserved.
 *
 */

#ifdef M_RCSID
#ifndef lint
static char rcsID[] = "$Header: /rd/src/libc/xcurses/rcs/wadd_wch.c 1.5 1995/07/26 17:43:19 ant Exp $";
#endif
#endif

#include <private.h>
#include <wctype.h>
#include <string.h>

/*f
 * Add a character (and attributes) to a window and advance the cursor.
 * Automatic newline done at right margin, tabs are expanded every 8 
 * columns, backspaces are handled.  Newline will clear the rest of the 
 * line; if nl() mode then the cursor is advanced to the start of the 
 * next line.
 */
int
wadd_wch(w, cc)
WINDOW *w;
const cchar_t *cc;
{
	cchar_t uc;
	const wchar_t *p;
	int code, x, y, nx;

#ifdef M_CURSES_TRACE
	__m_trace("wadd_wch(%p, %p) at (%d, %d)", w, cc, w->_cury, w->_curx);
#endif

	code = ERR;
	x = w->_curx;
	y = w->_cury;

	if (x < 0 || w->_maxx <= x || y < 0 || w->_maxy <= y)
		goto error;

	switch (cc->_wc[0]) {
	default:
		if (iswprint(cc->_wc[0])) {
	case '\t': 
	case '\n': 
	case '\b': 
	case '\r':
			if (__m_cc_add(w, y, x, cc, 0, &y, &x) == ERR)
				goto error;
			break;
		}

		/* Convert non-printables into printable representation. */
		uc._n = 1;
		uc._at = cc->_at;
		uc._co = cc->_co;

		if ((p = wunctrl(cc)) == (wchar_t *) 0)
			goto error;

		for ( ; *p != '\0'; ++p) {
			uc._wc[0] = *p;
			if (__m_cc_add(w, y, x, &uc, 0, &y, &x) == ERR)
				goto error;
		}
		break;
	}

	w->_curx = x;
	w->_cury = y;

	WSYNC(w);

	code = WFLUSH(w);
error:
	return __m_return_code("wadd_wch", code);
}

