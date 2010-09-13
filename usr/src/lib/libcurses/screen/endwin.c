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

/* Clean things up before exiting. */

#include	<stdlib.h>
#include	<sys/types.h>
#include	"curses_inc.h"

#ifdef	_VR2_COMPAT_CODE
char	_endwin = 0;
#endif	/* _VR2_COMPAT_CODE */

int
isendwin(void)
{
	/*
	 * The test below must stay at TRUE because the value of 2
	 * has special meaning to wrefresh but does not mean that
	 * endwin has been called.
	 */
	if (SP && (SP->fl_endwin == TRUE))
		return (TRUE);
	else
		return (FALSE);
}

int
endwin(void)
{
	/* make sure we're in program mode */
	if (SP->fl_endwin) {
		/* If endwin is equal to 2 it means we just did a newscreen. */
		if (SP->fl_endwin == TRUE) {
			(void) reset_prog_mode();
			if (SP->kp_state)
				(void) tputs(keypad_xmit, 1, _outch);
			if (SP->fl_meta)
				(void) tputs(meta_on, 1, _outch);
			if (cur_term->_cursorstate != 1)
				_PUTS(cur_term->cursor_seq
				    [cur_term->_cursorstate], 0);
		}
		_PUTS(enter_ca_mode, 1);
		(void) tputs(ena_acs, 1, _outch);
		if (exit_attribute_mode)
			_PUTS(tparm_p0(exit_attribute_mode), 1);
		else
			/*
			 * If there is no exit_attribute mode, then vidupdate
			 * could only possibly turn off one of the below three
			 * so that's all we ask it turn off.
			 */
			vidupdate(A_NORMAL,
			    (A_ALTCHARSET | A_STANDOUT | A_UNDERLINE), _outch);

		SP->fl_endwin = FALSE;

#ifdef	_VR2_COMPAT_CODE
		_endwin = (char) FALSE;
#endif	/* _VR2_COMPAT_CODE */
	}

	/* See comment above why this test is explicitly against TRUE. */
	if (SP->fl_endwin == TRUE)
		return (ERR);

	/* Flush out any output not output due to typeahead. */
	if (_INPUTPENDING)
		(void) force_doupdate();

	/* Close things down. */
	(void) ttimeout(-1);
	if (SP->fl_meta)
		(void) tputs(meta_off, 1, _outch);
	(void) mvcur(curscr->_cury, curscr->_curx, curscr->_maxy - 1, 0);

	if (SP->kp_state)
		(void) tputs(keypad_local, 1, _outch);
	if (cur_term->_cursorstate != 1)
		(void) tputs(cursor_normal, 0, _outch);

	/* don't bother turning off colors: it will be done later anyway */
	curscr->_attrs &= ~A_COLOR;		/* SS: colors */

	if ((curscr->_attrs != A_NORMAL) &&
	    (magic_cookie_glitch < 0) && (!ceol_standout_glitch))
		_VIDS(A_NORMAL, curscr->_attrs);

	if (SP->phys_irm)
		_OFFINSERT();

	SP->fl_endwin = TRUE;

#ifdef	_VR2_COMPAT_CODE
	_endwin = TRUE;
#endif	/* _VR2_COMPAT_CODE */

	curscr->_clear = TRUE;
	(void) reset_shell_mode();
	(void) tputs(exit_ca_mode, 0, _outch);

	/* restore colors and default color pair. SS: colors	*/
	if (orig_colors)
		(void) tputs(orig_colors, 1, _outch);
	if (orig_pair)
		(void) tputs(tparm_p0(orig_pair), 1, _outch);

	/* SS-mouse: free the mouse. */

	if (get_mouse)
		(void) tputs(tparm_p1(get_mouse, 0), 1, _outch);

	(void) fflush(SP->term_file);

	return (OK);
}

int
force_doupdate(void)
{
	char	chars_onQ = cur_term->_chars_on_queue;
	int	ret;

	/*
	 * This will cause _chkinput to return FALSE which will force wrefresh
	 * to think there is no input waiting and it will finish its refresh.
	 */

	cur_term->_chars_on_queue = INP_QSIZE;
	ret = doupdate();
	cur_term->_chars_on_queue = chars_onQ;
	return (ret);
}
