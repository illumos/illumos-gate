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
 * Copyright (c) 1995-1998 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/* LINTLIBRARY */

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
static char rcsID[] =
"$Header: /team/ps/sun_xcurses/archive/local_changes/xcurses/src/lib/"
"libxcurses/src/libc/xcurses/rcs/wadd_wch.c 1.5 1998/06/01 14:26:53 "
"cbates Exp $";
#endif
#endif

#include <private.h>

/* Special for calls from string add functions */
int
__m_wadd_wch(WINDOW *w, const cchar_t *cc)
{
	int	xsave = w->_curx;
	int	ysave = w->_cury;
	int	code = wadd_wch(w, cc);

	if (code == ERR) {
		w->_curx = (short) xsave;
		w->_cury = (short) ysave;
	}
	return (code);
}

/*
 * Add a character (and attributes) to a window and advance the cursor.
 * Automatic newline done at right margin, tabs are expanded every 8
 * columns, backspaces are handled.  Newline will clear the rest of the
 * line; if nl() mode then the cursor is advanced to the start of the
 * next line.
 */
int
wadd_wch(WINDOW *w, const cchar_t *cc)
{
	cchar_t	uc;
	const wchar_t	*p;
	int	code, x, y;
	int	oflags;

	oflags = w->_flags & (W_FLUSH | W_SYNC_UP);

	code = ERR;
	x = w->_curx;
	y = w->_cury;

	if (x < 0 || w->_maxx <= x || y < 0 || w->_maxy <= y)
		goto error;

	if (iswprint(cc->_wc[0]) || cc->_wc[0] == L'\n' ||
		cc->_wc[0] == L'\b' || cc->_wc[0] == L'\r') {
		if (__m_cc_add(w, y, x, cc, 0, &y, &x) == ERR)
			goto error;
	} else if (cc->_wc[0] == L'\t') {
		/*
		 * Experimental ...
		 * Maybe other cntrl chars should do this too ...
		 */
		if (__m_cc_add(w, y, x, cc, 0, &y, &x) == ERR) {
			w->_curx = (short) x;
			w->_cury = (short) y;
			WSYNC(w);
			WFLUSH(w);
			goto error;
		}
	} else {
		/* Convert non-printables into printable representation. */
		uc._n = 1;
		uc._at = cc->_at;
		uc._co = cc->_co;

		if ((p = wunctrl((cchar_t *)cc)) == NULL)
			goto error;

		for (; *p != '\0'; ++p) {
			uc._wc[0] = *p;
			if (__m_cc_add(w, y, x, &uc, 0, &y, &x) == ERR)
				goto error;
		}
	}

	w->_curx = (short) x;
	w->_cury = (short) y;

	WSYNC(w);

	code = WFLUSH(w);
error:
	w->_flags = oflags | (w->_flags & ~(W_FLUSH | W_SYNC_UP));

	return (code);
}
