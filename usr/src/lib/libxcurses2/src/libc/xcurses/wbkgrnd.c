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
 * wbkgrnd.c
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
"libxcurses/src/libc/xcurses/rcs/wbkgrnd.c 1.11 1998/05/29 14:48:51 "
"cbates Exp $";
#endif
#endif

#include <private.h>

/*
 * Combine the new background setting with every position in the window.
 * The background is any combination of attributes and a character.
 * Only the attribute part is used to set the background of non-blank
 * characters, while both character and attributes are used for blank
 * positions.
 */
int
wbkgrnd(WINDOW *w, const cchar_t *bg)
{
	short	y, x;
	short	acolor;
	cchar_t	old_bg, *cp;

	old_bg = w->_bg;
	w->_bg = *bg;
	w->_fg._at = (w->_fg._at & ~old_bg._at) | bg->_at;

	if ((acolor = w->_fg._co) != 0) {
		if (acolor == old_bg._co) {
			w->_fg._co = bg->_co;
		}
	} else {
		w->_fg._co = bg->_co;
	}

	for (y = 0; y < w->_maxy; ++y) {
		for (cp = w->_line[y], x = 0; x < w->_maxx; ++x, ++cp) {
			int	_at = cp->_at;

			old_bg._f = cp->_f;
			acolor = cp->_co;
			if (__m_cc_equal(cp, &old_bg)) {
				*cp = *bg;
			}
			if (acolor != 0) {
				if (acolor == old_bg._co) {
					cp->_co = bg->_co;
				} else {
					cp->_co = acolor;
				}
			} else {
				cp->_co = bg->_co;
			}
			cp->_at = (_at & ~old_bg._at) | bg->_at;
		}

		/* Mark line as touched. */
		w->_first[y] = 0;
		w->_last[y] = x;
	}

	WSYNC(w);

	return (WFLUSH(w));
}
