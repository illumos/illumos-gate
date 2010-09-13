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
/*	  All Rights Reserved  	*/

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
#ifdef	DEBUG
#include	<ctype.h>
#endif	/* DEBUG */

/*
 * This routine reads in a character from the window.
 *
 * wgetch MUST return an int, not a char, because it can return
 * things like ERR, meta characters, and function keys > 256.
 */

int
wgetch(WINDOW *win)
{
	int	inp;
	bool		weset = FALSE;

#ifdef	DEBUG
	if (outf) {
		fprintf(outf, "WGETCH: SP->fl_echoit = %c\n",
		    SP->fl_echoit ? 'T' : 'F');
		fprintf(outf, "_use_keypad %d, kp_state %d\n",
		    win->_use_keypad, SP->kp_state);
		fprintf(outf, "file %x fd %d\n", SP->input_file,
		    fileno(SP->input_file));
	}
#endif	/* DEBUG */

	if (SP->fl_echoit && cur_term->_fl_rawmode == 0) {
		(void) cbreak();
		weset++;
	}

	/* Make sure we are in proper nodelay state and not */
	/* in halfdelay state */
	if (cur_term->_delay <= 0 && cur_term->_delay != win->_delay)
		(void) ttimeout(win->_delay);

	if ((win->_flags & (_WINCHANGED | _WINMOVED)) && !(win->_flags &
	    _ISPAD))
		(void) wrefresh(win);

	if ((cur_term->_ungotten == 0) && (req_for_input)) {
		(void) tputs(req_for_input, 1, _outch);
		(void) fflush(SP->term_file);
	}
	inp = (int)tgetch((int)(win->_use_keypad ? 1 + win->_notimeout : 0));

	/* echo the key out to the screen */
	if (SP->fl_echoit && (inp < 0200) && (inp >= 0) && !(win->_flags &
	    _ISPAD))
		(void) wechochar(win, (chtype) inp);

	/*
	 * Do nl() mapping. nl() affects both input and output. Since
	 * we turn off input mapping of CR->NL to not affect input
	 * virtualization, we do the mapping here in software.
	 */
	if (inp == '\r' && !SP->fl_nonl)
		inp = '\n';

	if (weset)
		(void) nocbreak();

	return (inp);
}
