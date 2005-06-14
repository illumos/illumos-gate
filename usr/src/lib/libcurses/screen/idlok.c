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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
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

#include	<stdlib.h>
#include	"curses_inc.h"


/* Functions to make use of insert/delete line caps */

#define	scrco	COLS

typedef	struct
	{
	    int		_wy,	/* matching lines */
			_sy;
	} IDST;
static	IDST	*sid, *eid;		/* list of idln actions */
static	int	scrli,			/* screen dimensions */
		cy, cx;			/* current cursor positions */
static	bool	didcsr;			/* scrolling region was used */
static	int	_use_idln(void), _set_idln(void);
static	void	_do_idln(int, int, int, int);

/* Set insert/delete line mode for win */

int
idlok(WINDOW *win, bool bf)
{
	_useidln = _use_idln;
	_setidln = _set_idln;

	SP->yesidln = (delete_line || parm_delete_line ||
	    (change_scroll_region && (parm_index || scroll_forward))) &&
	    (insert_line || parm_insert_line ||
	    (change_scroll_region && (parm_rindex || scroll_reverse)));

	win->_use_idl = bf;
	return (OK);
}

/*
 * Set the places to do insert/delete lines
 * Return the start line for such action.
 */

static int
_set_idln(void)
{
	/*
	 * The value we want to return is the lower line
	 * number of the top-most range.
	 *
	 * If there is more than one range of lines on which
	 * we're operating, _find_idln will get called more
	 * then once; we need to search all the IDST for the
	 * desired return value.
	 */
	{
		IDST *idp;
		int rval = scrli;

		for (idp = sid; idp != eid; idp++) {
			int tmp;

			if ((tmp = _MIN(idp->_wy, idp->_sy)) < rval)
				rval = tmp;
		}
		return (rval);
	}
}

/* Use hardware line delete/insert */

static int
_use_idln(void)
{
	int	tsy, bsy, idn, dir, nomore;
	IDST	*ip, *ep, *eip;

	cy = curscr->_cury;
	cx = curscr->_curx;
	didcsr = FALSE;

	/* first cycle do deletions, second cycle do insertions */
	for (dir = 1; dir > -2; dir -= 2) {
		if (dir > 0) {
			ip = sid;
			eip = eid;
		} else {
			ip = eid - 1;
			eip = sid - 1;
		}

		nomore = TRUE;
		while (ip != eip) {
			/* skip deletions or insertions */
			if ((dir > 0 && ip->_wy > ip->_sy) ||
			    (dir < 0 && ip->_wy < ip->_sy)) {
				nomore = FALSE;
				ip += dir;
				continue;
			}

			/* find a contiguous block */
			for (ep = ip+dir; ep != eip; ep += dir)
				if (ep->_wy != (ep - dir)->_wy + dir ||
				    ep->_sy != (ep - dir)->_sy + dir) {
				    break;
			}
			ep -= dir;

			/* top and bottom lines of the affected region */
			if (dir > 0) {
				tsy = _MIN(ip->_wy, ip->_sy);
				bsy = _MAX(ep->_wy, ep->_sy) + 1;
			} else {
				tsy = _MIN(ep->_wy, ep->_sy);
				bsy = _MAX(ip->_wy, ip->_sy) + 1;
			}

			/* amount to insert/delete */
			if ((idn = ip->_wy - ip->_sy) < 0)
				idn = -idn;

			/* do the actual output */
			_do_idln(tsy, bsy, idn, dir == -1);

			/* update change structure */
			(void) wtouchln(_virtscr, tsy, bsy - tsy, -1);

			/* update screen image */
			/*LINTED*/
			curscr->_tmarg = (short)tsy;
			curscr->_bmarg = bsy - 1;
			/*LINTED*/
			curscr->_cury = (short)tsy;
			(void) winsdelln(curscr, dir > 0 ? -idn : idn);
			curscr->_tmarg = 0;
			curscr->_bmarg = scrli - 1;

			/* for next while cycle */
			ip = ep + dir;
		}

		if (nomore)
			break;
	}

	/* reset scrolling region */
	if (didcsr) {
		_PUTS(tparm_p2(change_scroll_region, 0, scrli - 1), scrli);
		cy = cx = -1;
	}

	/*LINTED*/
	curscr->_cury = (short)cy;
	/*LINTED*/
	curscr->_curx = (short)cx;
	return (OK);
}

/* Do the actual insert/delete lines */

static void
_do_idln(int tsy, int bsy, int idn, int doinsert)
{
	int	y, usecsr, yesscrl;
	short	*begns;

	/* change scrolling region */
	yesscrl = usecsr = FALSE;
	if (tsy > 0 || bsy < scrli) {
		if (change_scroll_region) {
		    _PUTS(tparm_p2(change_scroll_region, tsy, bsy - 1),
			bsy - tsy);
		    cy = cx = -1;
		    yesscrl = usecsr = didcsr = TRUE;
		}
	} else {
		if (didcsr) {
		    _PUTS(tparm_p2(change_scroll_region, 0, scrli - 1), scrli);
		    cy = cx = -1;
		    didcsr = FALSE;
		}
		yesscrl = TRUE;
	}

	if (doinsert) {
		/* memory below, clobber it now */
		if (memory_below && clr_eol &&
		    ((usecsr && non_dest_scroll_region) || bsy == scrli)) {
			for (y = bsy - idn, begns = _BEGNS + y;
			    y < bsy; ++y, ++begns)
				if (*begns < scrco) {
					(void) mvcur(cy, cx, y, 0);
					cy = y;
					cx = 0;
					_PUTS(clr_eol, 1);
				}
		}

		/* if not change_scroll_region, delete, then insert */
		if (!usecsr && bsy < scrli) {
			/* delete appropriate number of lines */
			(void) mvcur(cy, cx, bsy - idn, 0);
			cy = bsy - idn;
			cx = 0;
			if (parm_delete_line && (idn > 1 || !delete_line))
				_PUTS(tparm_p1(parm_delete_line, idn),
				    scrli - cy);
			else
				for (y = 0; y < idn; ++y)
			_PUTS(delete_line, scrli - cy);
		}

		/* now do insert */
		(void) mvcur(cy, cx, tsy, 0);
		cy = tsy;
		cx = 0;
		if (yesscrl) {
			if (!parm_rindex && (!scroll_reverse ||
			    (parm_insert_line && idn > 1))) {
				goto hardinsert;
			}
			if (parm_rindex && (idn > 1 || !scroll_reverse))
				_PUTS(tparm_p1(parm_rindex, idn), scrli - cy);
			else
				for (y = 0; y < idn; ++y)
					_PUTS(scroll_reverse, scrli - cy);
		} else {
hardinsert:
			if (parm_insert_line && (idn > 1 || !insert_line))
				_PUTS(tparm_p1(parm_insert_line, idn),
				    scrli - cy);
			else
				for (y = 0; y < idn; ++y)
					_PUTS(insert_line, scrli - cy);
		}
	} else {
		/* doing deletion */
		/* memory above, clobber it now */
		if (memory_above && clr_eol &&
		    ((usecsr && non_dest_scroll_region) || tsy == 0)) {
			for (y = 0, begns = _BEGNS + y + tsy;
			    y < idn; ++y, ++begns)
				if (*begns < scrco) {
					(void) mvcur(cy, cx, tsy + y, 0);
					cy = tsy + y;
					cx = 0;
					_PUTS(clr_eol, 1);
				}
		}

		if (yesscrl) {
			if (!parm_index && (!scroll_forward ||
			    (parm_delete_line && idn > 1))) {
				goto harddelete;
			}
			(void) mvcur(cy, cx, bsy - 1, 0);
			cy = bsy - 1;
			cx = 0;
			if (parm_index && (idn > 1 || !scroll_forward))
				_PUTS(tparm_p1(parm_index, idn), scrli - cy);
			else
				for (y = 0; y < idn; ++y)
					_PUTS(scroll_forward, scrli - cy);
		} else {
harddelete:
			/* do deletion */
			(void) mvcur(cy, cx, tsy, 0);
			cy = tsy;
			cx = 0;
			if (parm_delete_line && (idn > 1 || !delete_line))
				_PUTS(tparm_p1(parm_delete_line, idn),
				    scrli - cy);
			else
				for (y = 0; y < idn; ++y)
				    _PUTS(delete_line, scrli - cy);
		}

		/* if not change_scroll_region, do insert to restore bottom */
		if (!usecsr && bsy < scrli) {
			y = scrli - 1;
			begns = _BEGNS + y;
			for (; y >= bsy; --y, --begns)
				if (*begns < scrco)
					break;
			if (y >= bsy) {
				(void) mvcur(cy, cx, bsy - idn, 0);
				cy = bsy - idn;
				cx = 0;
				if (parm_insert_line &&
				    (idn > 1 || !insert_line))
					_PUTS(tparm_p1(parm_insert_line, idn),
					    scrli - cy);
				else
					for (y = 0; y < idn; ++y)
						_PUTS(insert_line, scrli - cy);
			}
		}
	}
}
