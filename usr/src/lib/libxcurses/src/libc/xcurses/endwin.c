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
 * endwin.c
 *
 * XCurses Library
 *
 * Copyright 1990, 1995 by Mortice Kern Systems Inc.  All rights reserved.
 *
 */

#ifdef M_RCSID
#ifndef lint
static char rcsID[] = "$Header: /rd/src/libc/xcurses/rcs/endwin.c 1.5 1995/07/19 16:37:58 ant Exp $";
#endif
#endif

#include <private.h>
#include <signal.h>


/*f
 * Restore tty modes, moves the cursor to the lower left hand 
 * corner of the screen and resets the terminal into proper non-visual 
 * mode.  Calling doupdate()/wrefresh() will resume visual mode. 
 */
int 
endwin()
{
#ifdef M_CURSES_TRACE
	__m_trace("endwin(void)");
#endif
	if (!(__m_screen->_flags & S_ENDWIN)) {
		__m_mvcur(-1, -1, lines-1, 0, __m_outc);

		if (exit_ca_mode != (char *) 0)
			(void) tputs(exit_ca_mode, 1, __m_outc);

		if (keypad_local != (char *) 0)
			(void) tputs(keypad_local, 1, __m_outc);

		if (orig_colors != (char *) 0)
			(void) tputs(orig_colors, 1, __m_outc);
		
		/* Make sure the current attribute state is normal.*/
		if (ATTR_STATE != WA_NORMAL) {
			(void) vid_puts(WA_NORMAL, 0, (void *) 0, __m_outc);

			if (ceol_standout_glitch)
				curscr->_line[curscr->_maxx-1][0]._at 
					|= WA_COOKIE;
		}

		(void) signal(SIGTSTP, SIG_DFL);
		__m_screen->_flags = S_ENDWIN;
	}

	(void) fflush(__m_screen->_of);
	(void) reset_shell_mode();

	return __m_return_code("endwin", OK);
}

