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
 * Copyright 1997 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved	*/

/*
 * University Copyright- Copyright (c) 1982, 1986, 1988
 * The Regents of the University of California
 * All Rights Reserved
 *
 * University Acknowledgment- Portions of this document are derived from
 * software developed by the University of California, Berkeley, and its
 * contributors.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*LINTLIBRARY*/

#include	<sys/types.h>
#include	"curses_inc.h"

/* Scroll the given window up/down n lines. */
int
wscrl(WINDOW *win, int n)
{
	short	curx, cury;
	bool	 savimmed, savsync;

#ifdef	DEBUG
	if (outf)
		if (win == stdscr)
			fprintf(outf, "scroll(stdscr, %d)\n", n);
		else
			if (win == curscr)
				fprintf(outf, "scroll(curscr, %d)\n", n);
			else
				fprintf(outf, "scroll(%x, %d)\n", win, n);
#endif	/* DEBUG */
	if (!win->_scroll || (win->_flags & _ISPAD))
		return (ERR);

	savimmed = win->_immed;
	savsync = win->_sync;
	win->_immed = win->_sync = FALSE;

	curx = win->_curx; cury = win->_cury;

	if (cury >= win->_tmarg && cury <= win->_bmarg)
		win->_cury = win->_tmarg;
	else
		win->_cury = 0;

	(void) winsdelln(win, -n);
	win->_curx = curx;
	win->_cury = cury;

	win->_sync = savsync;

	if (win->_sync)
		wsyncup(win);

	return ((win->_immed = savimmed) ? wrefresh(win) : OK);
}
