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
 * wins_wch.c
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
"libxcurses/src/libc/xcurses/rcs/wins_wch.c 1.3 1998/06/04 17:54:38 "
"cbates Exp $";
#endif
#endif

#include <private.h>
#include <string.h>

/*
 * Insert a character into a window line, shifting the line right
 * the column width of the inserted character.  The right most columns
 * will be truncated according to the width of the character inserted.
 */
int
__m_cc_ins(WINDOW *w, int y, int x, const cchar_t *cc)
{
	int	width;

	/* Determine the character width to insert. */
	if ((width = __m_cc_width(cc)) <= 0 || w->_maxx < x + width)
		return (-1);

	x = __m_cc_first(w, y, x);

	/*
	 * Use erase to remove possible multi-column chars
	 * before memmove clobbers them
	 */
	(void) __m_cc_erase(w, y, w->_maxx - width, y, w->_maxx - 1);

	/* Insert a "hole" into the line. */
	(void) memmove(&w->_line[y][x + width], &w->_line[y][x],
		(w->_maxx - x - width) * sizeof (**w->_line));

	/* Write the character into the hole. */
	if (__m_cc_replace(w, y, x, cc, 0) != width)
		return (-1);

	/* Update dirty region markers. */
	if (x < w->_first[y])
		w->_first[y] = (short) x;
	w->_last[y] = w->_maxx;

	/*
	 * If the last character on the line is incomplete,
	 * blank it out.
	 */
	x = __m_cc_first(w, y, w->_maxx-1);
	if (w->_maxx < x + __m_cc_width(&w->_line[y][x]))
		(void) __m_cc_erase(w, y, x, y, w->_maxx-1);

	return (width);
}

/*
 * Special internal version of wins_wch() that can track the cursor
 * position to facilitate inserting strings containing special characters
 * like \b, \n, \r, and \t.
 */
int
__m_wins_wch(WINDOW *w, int y, int x, const cchar_t *cc,
	int *yp, int *xp)
{
	cchar_t	uc;
	const wchar_t	*p;
	int	code, nx, width;

	code = ERR;

	switch (cc->_wc[0]) {
	case L'\r':
		x = 0;
		break;
	case L'\b':
		if (0 < x)
			--x;
		break;
	case L'\t':
		for (nx = x + (8 - (x & 07)); x < nx; x += width)
			if ((width = __m_cc_ins(w, y, x, &w->_bg)) <= 0)
				goto error;
		break;
	case L'\n':
		/* Truncate the tail of the current line. */
		if (__m_cc_erase(w, y, x, y, w->_maxx - 1) == -1)
			goto error;

		if (__m_do_scroll(w, y, x, &y, &x) == ERR)
			goto error;
		break;
	default:
		if (iswprint(cc->_wc[0])) {
			if ((width = __m_cc_ins(w, y, x, cc)) <= 0)
				goto error;
			x += width;
			break;
		}

		/* Convert non-printables into printable representation. */
		uc._n = 1;
		uc._at = cc->_at;
		uc._co = cc->_co;

		if ((p = wunctrl((cchar_t *)cc)) == NULL)
			goto error;

		for (; *p != '\0'; ++p, x += width) {
			uc._wc[0] = *p;
			if ((width = __m_cc_ins(w, y, x, &uc)) < 0)
				goto error;
		}
	}

	if (yp != NULL)
		*yp = y;
	if (xp != NULL)
		*xp = x;

	WSYNC(w);

	code = WFLUSH(w);
error:
	return (code);
}

/*
 * Insert a character (with attributes) before the cursor. All
 * characters to the right of the cursor are moved one space to
 * the right, with a possibility of the rightmost character on
 * the line being lost.  The cursor position does not change.
 */
int
wins_wch(WINDOW *w, const cchar_t *cc)
{
	int	code;

	code = __m_wins_wch(w, w->_cury, w->_curx, cc, NULL, NULL);

	return (code);
}
