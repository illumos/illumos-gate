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

/*
 * Duplicate a window.
 *
 * SS:	calling makenew to allocate a new window is wastefull, since
 *	makenew initializes all the variables, and then we re-initialize
 *	the desired values to these variables.
 */

WINDOW	*
dupwin(WINDOW *win)
{
	WINDOW		*new;
	int		i, ncolumns = win->_maxx, nlines = win->_maxy;
	size_t		line_size = nlines * sizeof (short);
	chtype		**wincp, **newcp;
	int		ncolsav = ncolumns;

	/* allocate storage for new window and do block copy of */
	/* old one into new */

	if ((new = (WINDOW *) malloc(sizeof (WINDOW))) == NULL)
		goto out0;

	(void) memcpy(new, win, sizeof (WINDOW));

	/* allocate storage for "malloced" fields of the new window */

	if ((new->_firstch = (short *)malloc((unsigned)2 * line_size)) == NULL)
		goto out1;
	else
		win->_lastch = win->_firstch + nlines;

	if ((new->_y = (chtype **) malloc(nlines * sizeof (chtype *))) ==
	    NULL) {
	/*
	 * We put the free's here rather than after the image call, this
	 * is because _image free's all the rest of the malloc'ed areas.
	 */
		free((char *)new->_firstch);
out1:
		free((char *)new);
		goto out0;
	}

	if (_image(new) == ERR) {
out0:
		curs_errno = CURS_BAD_MALLOC;
#ifdef	DEBUG
		strcpy(curs_parm_err, "dupwin");
		curserr();
#endif	/* DEBUG */
		return ((WINDOW *) NULL);
	}

	/* copy information from "malloced" areas of the old window into new */

	wincp = win->_y;
	newcp = new->_y;
	for (i = 0; i < nlines; ++i, ++wincp, ++newcp) {
		chtype		*ws, *we, *ns, *ne, wc;
		int		n;

		ws = *wincp;
		we = ws + ncolsav - 1;
		/* skip partial characters */
		for (; ws <= we; ++ws)
			if (!ISCBIT(*ws))
				break;
		for (; we >= ws; --we)
			if (!ISCBIT(*we))
				break;
		if (we >= ws) {
			wc = *we;
			n = _curs_scrwidth[TYPE(wc)];
			if ((we + n) <= (*wincp + ncolsav))
				we += n;
			ns = *newcp + (ws - *wincp);
			ne = *newcp + (we - *wincp);
			(void) memcpy((char *)ns, (char *)ws,
			    (ne-ns)*sizeof (chtype));
		} else
			ns = ne = *newcp + ncolsav;
		/* fill the rest with background chars */
		wc = win->_bkgd;
		for (ws = *newcp; ws < ns; ++ws)
			*ws = wc;
		for (ws = *newcp+ncolsav-1; ws >= ne; --ws)
			*ws = wc;
	}

	(void) memcpy((char *)new->_firstch, (char *)win->_firstch,
	    2 * line_size);

	new->_flags |= _WINCHANGED;
	new->_ndescs = 0;
	/*
	 * Just like we don't create this window as a subwin if the one
	 * sent is, we don't create a padwin.  Besides, if the user
	 * calls p*refresh a padwin will be created then.
	 */
	new->_padwin = new->_parent = (WINDOW *) NULL;
	new->_pary = new->_parx = -1;

	new->_index = win->_index;
	new->_nbyte = win->_nbyte;
	new->_insmode = win->_insmode;
	(void) memcpy((char *)new->_waitc, (char *)win->_waitc,
	    _csmax * sizeof (char));

	return (new);
}
