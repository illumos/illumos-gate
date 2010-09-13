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
 * wrefresh.c
 *
 * XCurses Library
 *
 * Copyright 1990, 1995 by Mortice Kern Systems Inc.  All rights reserved.
 *
 */

#ifdef M_RCSID
#ifndef lint
static char rcsID[] = "$Header: /rd/src/libc/xcurses/rcs/wrefresh.c 1.3 1995/06/20 14:34:14 ant Exp $";
#endif
#endif

#include <private.h>
#include <string.h>

/*f
 * Update curscr with the given window then display to the terminal. 
 * Unless leaveok() has been enabled, the physical cursor of the 
 * terminal is left at the location of the cursor for that window.
 */
int
wrefresh(w)
WINDOW *w;
{
	int value;

#ifdef M_CURSES_TRACE
	__m_trace("wrefresh(%p)", w);
#endif
	if (w == curscr)
		value = clearok(__m_screen->_newscr, TRUE);
	else
		value = wnoutrefresh(w);

	if (value == OK)
		value = doupdate();

	return __m_return_code("wrefresh", value);
}

/*f
 * Update newscr with the given window.  This allows newscr to be 
 * updated with several windows before doing a doupdate() (and so 
 * improve the efficiency of multiple updates in comparison to 
 * looping through wrefresh() for all windows).
 */
int
wnoutrefresh(w)
WINDOW *w;
{
	int wy, wx, ny, nx, dx, value;
	WINDOW *ns = __m_screen->_newscr;

#ifdef M_CURSES_TRACE
	__m_trace("wnoutrefresh(%p)", w);
#endif

	value = (w->_flags & W_IS_PAD) ? ERR : OK;

	if (value == OK) {
		/* This loop is similar to what copywin() does, except that
		 * this loop only copies dirty lines, while copywin() copies
		 * every line.
		 */
		for (wy = 0, ny = w->_begy; wy < w->_maxy; ++wy, ++ny) {
			/* Has line been touched? */
			if (w->_last[wy] <= w->_first[wy])
				continue;

			wx = w->_first[wy];
			nx = w->_begx + wx;
			dx = w->_last[wy] - wx;

			/* Case 3 - Check target window for overlap of broad
			 * characters around the outer edge of the source
			 * window's location.  
			 */
			(void) __m_cc_erase(ns, ny, nx, ny, nx);
			(void) __m_cc_erase(ns, ny, nx+dx-1, ny, nx+dx-1);

                        (void) memcpy(
                                &ns->_line[ny][nx], &w->_line[wy][wx],
                                dx * sizeof **w->_line
                        );

			if (!ns->_line[ny][nx]._f) {
				/* Case 5 - Incomplete glyph copied from 
				 * source at screen margins.
				 */
				if (nx <= 0)
					(void) __m_cc_erase(ns, ny, 0, ny, 0);
#ifdef M_CURSES_SENSIBLE_WINDOWS
				/* Case 4 - Expand incomplete glyph from 
				 * source into target window.
				 */
				else if (0 < nx)
					(void) __m_cc_expand(ns, ny, nx, -1);
#endif /* M_CURSES_SENSIBLE_WINDOWS */
			}

			if (!__m_cc_islast(ns, ny, nx+dx-1)) {
				/* Case 5 - Incomplete glyph copied from 
				 * source at screen margins.
				 */
				if (ns->_maxx <= nx + dx)
					(void) __m_cc_erase(
						ns, ny, nx+dx-1, ny, nx+dx-1
					);
#ifdef M_CURSES_SENSIBLE_WINDOWS
				/* Case 4 - Expand incomplete glyph from 
				 * source into target window.
				 */
				else if (nx + dx < ns->_maxx)
					(void) __m_cc_expand(
						ns, ny, nx+dx-1, 1
					);
#endif /* M_CURSES_SENSIBLE_WINDOWS */
			}
			
			/* Untouch line. */
			w->_first[wy] = w->_maxx;
			w->_last[wy] = -1;

			/* Remember refresh region (inclusive). */
			w->_refy = w->_begy;
			w->_refx = w->_begx;
			w->_sminy = w->_sminx = 0;
			w->_smaxy = ns->_maxy-1;
			w->_smaxx = ns->_maxx-1;
		}

		ns->_scroll = w->_scroll;
		w->_scroll = 0;

		/* Last refreshed window controls W_LEAVE_CURSOR flag. */
		ns->_flags &= ~W_LEAVE_CURSOR;
		ns->_cury = w->_cury + w->_begy;
		ns->_curx = w->_curx + w->_begx;

		ns->_flags |= w->_flags 
			& (W_CLEAR_WINDOW | W_REDRAW_WINDOW | W_LEAVE_CURSOR);
		w->_flags &= ~(W_CLEAR_WINDOW | W_REDRAW_WINDOW);
	}

	return __m_return_code("wnoutrefresh", value);
}

/*
 * Check overlaping region on a line.
 *
 * When copying a source window region over another target window 
 * region, we have a few cases which to concern ourselves with.
 *
 * Let {, [, ( and ), ], } denote the left and right halves of
 * broad glyphes.
 *
 * Let alpha-numerics and periods (.) be narrow glyphes.
 *
 * Let hash (#) be a narrow background character.
 *
 * Let vertical bar, hyphen, and plus represent the borders 
 * of a window.
 *
 *  1.	Copy narrow characters over narrow characters.
 *		copywin(s, t, 0, 1, 0, 1, 1, 3, 0)
 *		   s      	   t      ==>      t 
 *		+------+	+------+	+------+
 *		|abcdef|	|......|	|.bcd..|
 *		|ghijkl|	|......|	|.hij..|
 *		|mnopqr|	|......|	|......|
 *		+------+	+------+	+------+
 *	Nothing special.
 *
 *  2.	Copy whole broad characters over narrow characters.
 *		copywin(s, t, 0, 1, 0, 1, 1, 3, 0)
 *		   s               t       ==>     t 
 *		+------+	+------+	+------+
 *		|a[]def|	|......|	|.[]d..|
 *		|gh{}kl|	|......|	|.h{}..|
 *		|mnopqr|	|......|	|......|
 *		+------+	+------+	+------+
 *	Nothing special.
 *
 *  3.	Copy narrow from source overlaps broad in target.
 *		copywin(s, t, 0, 1, 0, 1, 1, 3, 0)
 *		   s               t       ==>     t 
 *		+------+	+------+	+------+
 *		|abcdef|	|[]....|	|#bcd..|
 *		|ghijkl|	|...{}.|	|.hij#.|
 *		|mnopqr|	|......|	|......|
 *		+------+	+------+	+------+
 *	The # background characters have wiped out the remaining
 *	halves of broad characters.  This may result also with
 *	a wnoutrefresh() of a window onto curscr.
 *
 * The following case appears to be disallowed in XPG4 V2 
 * and I think they're wrong, so I've conditionalised the code 
 * on M_CURSES_SENSIBLE_WINDOWS.
 *
 *  4.	Copy incomplete broad from source to target.
 *		copywin(s, t, 0, 1, 0, 1, 1, 3, 0)
 *		   s               t       ==>     t 
 *		+------+	+------+	+------+
 *		|[]cdef|	|123456|	|[]cd56|
 *		|ghi{}l|	|789012|	|7hi{}2|
 *		|mnopqr|	|......|	|......|
 *		+------+	+------+	+------+
 *	The ] and { halves of broad characters have been copied and
 *	expanded into the target outside of the specified target region.
 *	This may result also with a wnoutrefresh() of a window onto
 *	curscr.
 *
 * Consider a pop-up dialog that contains narrow characters and
 * a base window that contains broad characters and we do the
 * following:
 * 	
 * 	save = dupwin(dialog);		// create backing store
 * 	overwrite(curscr, save);	// save region to be overlayed
 * 	wrefresh(dialog);		// display dialog
 * 	...				// do dialog stuff
 * 	wrefresh(save);			// restore screen image
 * 	delwin(save);			// release backing store
 *
 * Code similar to this has been used to implement generic popup()
 * and popdown() routines.  In the simple case where the base window
 * contains narrow characters only, it would be correctly restored.
 *
 * However with broad characters, the overwrite() could copy a
 * region with incomplete broad characters.  The wrefresh(dialog) 
 * results in case 3.  In order to restore the window correctly with
 * wrefresh(save), we require case 4.
 *
 *  5.	Copy incomplete broad from source to target region next to margin.
 *
 *	a)
 *		copywin(s, t, 0, 1, 0, 0, 1, 2, 0)
 *		   s               t       ==>     t 
 *		+------+	+------+	+------+
 *		|[]cdef|	|123456|	|#cd456|
 *		|ghijkl|	|789012|	|hij012|
 *		|mnopqr|	|......|	|......|
 *		+------+	+------+	+------+
 *	The # background character has replaced the ] character that
 *	would have been copied from the source, because it is not possible
 *	to expand the broad character to its complete form (case 4).
 *
 *	b)
 *		copywin(s, t, 0, 1, 0, 3, 1, 5, 0)
 *		   s               t       ==>     t 
 *		+------+	+------+	+------+
 *		|abcdef|	|123456|	|123bcd|
 *		|ghi{}l|	|789012|	|789hi#|
 *		|mnopqr|	|......|	|......|
 *		+------+	+------+	+------+
 *	Same a 5a. but with the right margin.
 */
