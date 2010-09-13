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
/*  Copyright (c) 1988 AT&T */
/*    All Rights Reserved   */


/*
 *      Copyright (c) 1997, by Sun Microsystems, Inc.
 *      All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*LINTLIBRARY*/

#include	<sys/types.h>
#include	"curses_inc.h"

int
winwstr(WINDOW *win, wchar_t *wstr)
{
	int	counter = 0;
	int	cy = win->_cury;
	chtype	*ptr = &(win->_y[cy][win->_curx]),
		*pmax = &(win->_y[cy][win->_maxx]);
	chtype	*p1st = &(win->_y[cy][0]);
	wchar_t	wc;
	int	sw, s;
	char	*cp, cbuf[CSMAX+1];

	while (ISCBIT(*ptr) && (p1st < ptr))
		ptr--;

	while (ptr < pmax) {
		wc = RBYTE(*ptr);
		sw = mbscrw((int)wc);
		(void) mbeucw((int)wc);

		cp = cbuf;
		for (s = 0; s < sw; s++, ptr++) {
			if ((wc = RBYTE(*ptr)) == MBIT)
				continue;
			/* LINTED */
			*cp++ = (char) wc;
			if ((wc = LBYTE(*ptr) | MBIT) == MBIT)
				continue;
			/* LINTED */
			*cp++ = (char) wc;
		}
		*cp = '\0';

		if (_curs_mbtowc(&wc, cbuf, CSMAX) <= 0)
			break;

		*wstr++ = wc;
	}

	*wstr = (wchar_t)0;

	return (counter);
}
