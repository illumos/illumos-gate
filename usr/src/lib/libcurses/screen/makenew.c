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

#include	<stdlib.h>
#include	<string.h>
#include	<sys/types.h>
#include	"curses_inc.h"

/* This routine sets up a window buffer and returns a pointer to it. */

WINDOW	*
_makenew(int nlines, int ncols, int begy, int begx)
{
	/* order the register allocations against highest usage */
	WINDOW	*win;

#ifdef	DEBUG
	if (outf)
		fprintf(outf, "MAKENEW(%d, %d, %d, %d)\n",
		    nlines, ncols, begy, begx);
#endif	/* DEBUG */

	if ((win = (WINDOW *) malloc(sizeof (WINDOW))) == NULL)
		goto out_no_win;
	if ((win->_y = (chtype **) malloc(nlines * sizeof (chtype *))) == NULL)
		goto out_win;
#ifdef	_VR3_COMPAT_CODE
	if ((_y16update) && ((win->_y16 = (_ochtype **)
	    calloc(1, nlines * sizeof (_ochtype *))) == NULL)) {
		goto out_y16;
	}
#endif	/* _VR3_COMPAT_CODE */
	if ((win->_firstch = (short *) malloc(2 * nlines * sizeof (short)))
	    == NULL) {
#ifdef	_VR3_COMPAT_CODE
		if ((_y16update) && (win->_y16 != NULL))
			free((char *) win->_y16);
out_y16:
#endif	/* _VR3_COMPAT_CODE */
		free((char *) win->_y);
out_win:
		free((char *) win);
out_no_win:
		curs_errno = CURS_BAD_MALLOC;
#ifdef	DEBUG
		strcpy(curs_parm_err, "_makenew");
#endif	/* DEBUG */
		return ((WINDOW *) NULL);
	} else
		win->_lastch = win->_firstch + nlines;

	win->_cury = win->_curx = 0;
	/*LINTED*/
	win->_maxy = (short) nlines;
	/*LINTED*/
	win->_maxx = (short) ncols;
	/*LINTED*/
	win->_begy = (short) begy;
	/*LINTED*/
	win->_begx = (short) begx;
	win->_clear = (((begy + SP->Yabove + begx) == 0) &&
	    (nlines >= (LINES + SP->Yabove)) && (ncols >= COLS));
	win->_leave = win->_scroll = win->_use_idl = win->_use_keypad =
	    win->_notimeout = win->_immed = win->_sync = FALSE;
	win->_use_idc = TRUE;
	win->_ndescs = win->_tmarg = 0;
	win->_bmarg = nlines - 1;
	win->_bkgd = _BLNKCHAR;
	win->_delay = win->_parx = win->_pary = -1;
	win->_attrs = A_NORMAL;
	win->_flags = _WINCHANGED;
	win->_parent = win->_padwin = (WINDOW *) NULL;
	(void) memset((char *) win->_firstch, 0, (nlines * sizeof (short)));
	{
		short	*lastch = win->_lastch,
			*elastch = lastch + nlines;

		ncols--;
		while (lastch < elastch)
		    /*LINTED*/
		    *lastch++ = (short) ncols;
	}

	win->_insmode = FALSE;
	win->_index = 0;
	win->_nbyte = -1;

#ifdef	DEBUG
	if (outf) {
		fprintf(outf, "MAKENEW: win->_clear = %d\n", win->_clear);
		fprintf(outf, "MAKENEW: win->_flags = %0.2o\n", win->_flags);
		fprintf(outf, "MAKENEW: win->_maxy = %d\n", win->_maxy);
		fprintf(outf, "MAKENEW: win->_maxx = %d\n", win->_maxx);
		fprintf(outf, "MAKENEW: win->_begy = %d\n", win->_begy);
		fprintf(outf, "MAKENEW: win->_begx = %d\n", win->_begx);
	}
#endif	/* DEBUG */
	return (win);
}
