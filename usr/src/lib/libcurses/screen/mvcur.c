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

/*
 * Cursor motion optimization routine.  This routine takes as parameters
 * the screen positions that the cursor is currently at, and the position
 * you want it to be at, and it will move the cursor there very
 * efficiently.  It isn't really optimal, since several approximations
 * are taken in the interests of efficiency and simplicity.  The code
 * here considers directly addressing the cursor, and also considers
 * local motions using left, right, up, down, tabs, backtabs, vertical
 * and horizontal addressing, and parameterized motions.  It does not
 * consider using home down, or taking advantage of automatic margins on
 * any of the four directions.  (Two of these directions, left and right,
 * are well defined by the am and bw capabilities, but up and down are
 * not defined, nor are tab or backtab off the ends.)
 *
 * General strategies considered:
 *	CA	Direct Cursor Addressing
 *	LM	Local Motions from the old position
 *	HR	Home + Local Motions from upper left corner
 *	HDR	Home Down + Local Motions from lower left corner
 *	CR	CR + Local Motions from left margin
 *
 * Local Motions can include
 *	Up	cuu, cuu1, vpa
 *	Down	cud, cud1, vpa
 *	Left	cul, cul1, hpa, bs, cbt
 *	Right	cuf, cuf1, hpa, tab, char moved over
 */

/* This is called _ISMARK2 so it doesn't conflict with _ISMARK1 in wrefresh.c */

#define	_ISMARK2(x)	(mks[(x) / BITSPERBYTE] & (1<<((x) % BITSPERBYTE)))

#define	H_UP	-1
#define	H_DO	1

static	int	Newy;
static  int	_homefirst(int, int, int, int),
		_mvrel(int, int, int, int, int),
		_mvvert(int, int, int), _mvhor(int, int, int),
		_mvright(int, int, int), _mvleft(int, int, int);

int
mvcur(int cury, int curx, int newy, int newx)
{
	int	hu,	/* cost home + relative */
		hd,	/* cost home-down + relative */
		rl,	/* cost relative */
		cm;	/* cost direct cursor motion */

	/* obvious case */
	if (cury == newy && curx == newx)
		return (OK);

	/* not in the right mode for cursor movement */
	if (SP->fl_endwin)
		return (ERR);

	if (!move_standout_mode && curscr->_attrs && !SP->_mks)
		_VIDS(A_NORMAL, curscr->_attrs);

	if (!move_insert_mode && SP->phys_irm)
		_OFFINSERT();

	Newy = newy;

	/* cost of using cm */
	cm = _COST(Cursor_address);

	rl = hd = hu = LARGECOST;

	/* baudrate optimization */
	if (cm < LARGECOST && SP->baud >= 2400 &&
	    cury >= 0 && cury < curscr->_maxy &&
	    curx >= 0 && curx < curscr->_maxx) {
		if (cursor_down && (newy == (cury + 1)) &&
		    ((newx == curx) || (newx == 0 && carriage_return))) {
			if (newx != curx)
				_PUTS(carriage_return, 1);
			_PUTS(cursor_down, 1);
			goto done;
		}

		/* fast horizontal move */
		if (cury == newy && newx < curx - 4 && newx > curx + 4) {
			if (newx < curx)
				rl = _mvleft(curx, newx, FALSE);
			else
				rl = _mvright(curx, newx, FALSE);
			if (rl < cm) {
				if (newx < curx)
					rl = _mvleft(curx, newx, TRUE);
				else
					rl = _mvright(curx, newx, TRUE);
				goto done;
			}
		}
	}

	/* cost using relative movements */
	if (rl >= LARGECOST && cury >= 0 && cury < curscr->_maxy &&
	    curx >= 0 && curx < curscr->_maxx)
		rl = _mvrel(cury, curx, newy, newx, FALSE);

	/* cost of homing to upper-left corner first */
	if (cursor_home)
		hu = _homefirst(newy, newx, H_UP, FALSE);

	/* cost of homing to lower-left corner first */
	if (cursor_to_ll)
		hd = _homefirst(newy, newx, H_DO, FALSE);

	/* can't do any one of them */
	if (cm >= LARGECOST && rl >= LARGECOST && hu >= LARGECOST &&
	    hd >= LARGECOST)
		return (ERR);

	/* do the best one */
	if (cm <= rl && cm <= hu && cm <= hd)
		_PUTS(tparm_p2(cursor_address, newy, newx), 1);
	else
		if (rl <= hu && rl <= hd)
			(void) _mvrel(cury, curx, newy, newx, TRUE);
		else
			(void) _homefirst(newy, newx, hu <= hd ?
			    H_UP : H_DO, TRUE);

done:
	/* update cursor position */
	/*LINTED*/
	curscr->_curx = (short) newx;
	/*LINTED*/
	curscr->_cury = (short) newy;

	return (OK);
}

/* Move by homing first. */

static int
_homefirst(int ny, int nx, int type, int doit)
{
	char	*home;
	int	cy, cost;

	if (type == H_UP) {
		home = cursor_home;
		cost = _COST(Cursor_home);
		cy = 0;
	} else {
		home = cursor_to_ll;
		cost = _COST(Cursor_to_ll);
		cy = curscr->_maxy - 1;
	}

	if (!home)
		return (LARGECOST);
	if (!doit)
		return (cost + _mvrel(cy, 0, ny, nx, FALSE));

	_PUTS(home, 1);
	return (_mvrel(cy, 0, ny, nx, TRUE));
}

/* Move relatively */

static int
_mvrel(int cy, int cx, int ny, int nx, int doit)
{
	int	cv, ch;

	/* do in this order since _mvhor may need the curscr image */
	cv = _mvvert(cy, ny, doit);
	ch = _mvhor(cx, nx, doit);

	return (cv + ch);
}

/* Move vertically */

static int
_mvvert(int cy, int ny, int doit)
{
	char	*ve;
	int	dy, st_1, st_n, cv;

	if (cy == ny)
		goto out;

	/* cost of stepwise movement */
	if (cy < ny) {
		dy = ny-cy;
		st_1 = _COST(Cursor_down) * dy;
		st_n = _COST(Parm_down_cursor);
	} else {
		dy = cy-ny;
		st_1 = _COST(Cursor_up) * dy;
		st_n = _COST(Parm_up_cursor);
	}

	/* cost of using vertical move */
	cv = _COST(Row_address);

	/* if calculating cost only */
	if (!doit)
		return ((cv < st_1 && cv < st_n) ? cv :
		    (st_n < st_1) ? st_n : st_1);

	/* do it */
	if (cv < st_1 && cv < st_n)
		_PUTS(tparm_p1(row_address, ny), 1);
	else
		if (st_n < st_1) {
			if (cy < ny)
				_PUTS(tparm_p1(parm_down_cursor, dy), 1);
			else
				_PUTS(tparm_p1(parm_up_cursor, dy), 1);
		} else {
			if (cy < ny)
				ve = cursor_down;
			else
				ve = cursor_up;
			for (; dy > 0; --dy)
				_PUTS(ve, 1);
		}

out:
	return (0);
}

/* Move horizontally */

static int
_mvhor(int cx, int nx, int doit)
{
	int	st, ch, hl;

	if (cx == nx)
		goto out;

	/* cost using horizontal move */
	ch = _COST(Row_address);

	/* cost doing stepwise */
	st = cx < nx ? _mvright(cx, nx, FALSE) : _mvleft(cx, nx, FALSE);

	/* cost homeleft first */
	hl = (_COST(Carriage_return) < LARGECOST) ?
	    _COST(Carriage_return) + _mvright(0, nx, FALSE) : LARGECOST;

	if (!doit)
		return ((ch < st && ch < hl) ? ch : (hl < st ? hl : st));

	if (ch < st && ch < hl)
		_PUTS(tparm_p1(column_address, nx), 1);
	else
		if (hl < st) {
			_PUTS(carriage_return, 1);
			(void) _mvright(0, nx, TRUE);
		} else {
			if (cx < nx)
				(void) _mvright(cx, nx, TRUE);
			else
				(void) _mvleft(cx, nx, TRUE);
	}
out:
	return (0);
}

/* Move right. */

static int
_mvright(int cx, int nx, int doit)
{
	chtype	*scp;
	char	*mks;
	int	nt, tx, x, stcost, iscont;

	if (!cursor_right && !parm_right_cursor)
		return (LARGECOST);

	scp = curscr->_y[Newy];
	mks = magic_cookie_glitch >= 0 ? SP->_mks[Newy] : NULL;

	if (cursor_right) {
		/* number of tabs used in stepwise movement */
		nt = tab ? (nx / TABSIZE - cx / TABSIZE) : 0;
		tx = (nt > 0) ? (cx / TABSIZE + nt) * TABSIZE : cx;

		/* calculate stepwise cost */
		stcost = nt * _COST(Tab);
		iscont = 0;
		for (x = tx; x < nx; ++x) {
			if (iscont == 0 && !ISCBIT(scp[x]))
				iscont = 1;
			if ((!ceol_standout_glitch && !mks &&
			    _ATTR(scp[x]) == curscr->_attrs) ||
			    ceol_standout_glitch || (mks && !_ISMARK2(x))) {
				if (!ISMBIT(scp[x]))
					stcost += 1;
				else if (iscont && !(nx - x == 1 && nx <
				    curscr->_maxx && ISCBIT(scp[nx])))
					stcost += 1;
				else
					stcost += _COST(Cursor_right);
			} else
				stcost += _COST(Cursor_right);
		}
	} else
		stcost = LARGECOST;

	if (!doit)
		return ((_COST(Parm_right_cursor) < stcost) ?
		    _COST(Parm_right_cursor) : stcost);

	/* actually move */
	if (_COST(Parm_right_cursor) < stcost)
		_PUTS(tparm_p1(parm_right_cursor, nx-cx), 1);
	else {
		if (SP->phys_irm)
			_OFFINSERT();
		for (; nt > 0; --nt)
			_PUTS(tab, 1);
		iscont = 0;
		for (x = tx; x < nx; ++x) {
			if (iscont == 0 && !ISCBIT(scp[x]))
				iscont = 1;
			if ((!ceol_standout_glitch && !mks &&
			    _ATTR(scp[x]) == curscr->_attrs) ||
			    ceol_standout_glitch || (mks && !_ISMARK2(x))) {
				if (!ISMBIT(scp[x]))
					(void) _outwch(_CHAR(scp[x]));
				else if (iscont && !(nx - x == 1 &&
				    nx < curscr->_maxx && ISCBIT(scp[nx])))
					(void) _outwch(_CHAR(scp[x]));
				else
					_PUTS(cursor_right, 1);
			} else
				_PUTS(cursor_right, 1);
		}
	}

	return (0);
}

/* Move left */

static int
_mvleft(int cx, int nx, int doit)
{
	int	tx, nt, x, stcost;

	if (!cursor_left && !parm_left_cursor)
		return (LARGECOST);

	if (cursor_left) {
		/* stepwise cost */
		tx = cx;
		nt = 0;
		if (back_tab) {
			/* the TAB position >= nx */
			x = (nx % TABSIZE) ? (nx / TABSIZE + 1) * TABSIZE : nx;

			/* # of tabs used and position after using them */
			if (x < cx) {
				nt = (cx / TABSIZE - x / TABSIZE) +
				    ((cx % TABSIZE) ? 1 : 0);
				tx = x;
			}
		}
		stcost = nt * _COST(Back_tab) + (tx-nx) * _COST(Cursor_left);
	} else
		stcost = LARGECOST;

	/* get cost only */
	if (!doit)
		return ((_COST(Parm_left_cursor) < stcost) ?
		    _COST(Parm_left_cursor) : stcost);

	/* doit */
	if (_COST(Parm_left_cursor) < stcost)
		_PUTS(tparm_p1(parm_left_cursor, cx - nx), 1);
	else {
		for (; nt > 0; --nt)
		    _PUTS(back_tab, 1);
		for (; tx > nx; --tx)
		    _PUTS(cursor_left, 1);
	}

	return (0);
}
