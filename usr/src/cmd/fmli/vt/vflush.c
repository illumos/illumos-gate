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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include	<curses.h>
#include	"wish.h"
#include	"vt.h"
#include	"vtdefs.h"
#include	"attrs.h"
#include	"color_pair.h"

extern int Refresh_slks;

extern int Color_terminal;
static void vt_title();
static void vt_scroll_arrow();
static void vt_page_arrow();
static void vt_display(void);

void
vt_flush()
{
/*
	_debug3(stderr, "\t--==[ FLUSHING ]==--\n");
*/
	vt_display();
	if (Refresh_slks) {
		Refresh_slks = 0;
		slk_restore();	
	}
	if (VT_front >= 0)
		wnoutrefresh(VT_array[VT_front].win);
	doupdate();
/*
	_debug3(stderr, "\t--==[ FINISHED ]==--\n");
*/
}

static void
vt_display(void)
{
	register struct vt	*v;
	int colattr;
	vt_id	vid;

	for ( vid = VT_back; vid != VT_UNDEFINED; vid = v->prev )
	{
		v = &VT_array[vid];

		if ( !(v->flags & VT_ANYDIRTY))
			continue;
	
		if (!(v->flags & VT_NOBORDER)) {
			int	row, col;
	
			if (v->flags & VT_BDIRTY)	/* border dirty */
			{
				getyx(v->win, row, col);
				if (vid == VT_curid)
					colattr = ACTIVE_BORD_PAIR;
				else
					colattr = INACTIVE_BORD_PAIR;
				wattrset(v->win, COL_ATTR(A_NORMAL, colattr));
				box(v->win, 0, 0);
				wattrset(v->win, COL_ATTR(A_NORMAL, WINDOW_PAIR));
				v->flags |= VT_TDIRTY | VT_PADIRTY | VT_SADIRTY;
				wmove(v->win, row, col);
			}

			if (v->flags & VT_TDIRTY)	/* title dirty */
			{
				getyx(v->win, row, col);
				if (vid == VT_curid)
					vt_title(v, TRUE);
				else
					vt_title(v, FALSE);
				wmove(v->win, row, col);
			}

			if (v->flags & VT_PADIRTY)	/* page arrow dirty */
			{
				getyx(v->win, row, col);
				if (vid == VT_curid)
					vt_page_arrow(v, TRUE);
				else
					vt_page_arrow(v, FALSE);
				wmove(v->win, row, col);
			}
			if (v->flags & VT_SADIRTY)	/* scroll arrow dirty */
			{
				getyx(v->win, row, col);
				if (vid == VT_curid)
					vt_scroll_arrow(v, TRUE);
				else
					vt_scroll_arrow(v, FALSE);
				wmove(v->win, row, col);
			}
		}
		{
			int	sr1, sc1, r1, c1;
			int	sr2, sc2, r2, c2;
			register vt_id	ov;
			register struct vt	*vp;
/*	
			_debug3(stderr, "flushing %d(#%d) flags = 0x%x\n", vid, v->number, v->flags);
*/
			wnoutrefresh(v->win);
			getbegyx(v->win, sr1, sc1);
			getmaxyx(v->win, r1, c1);
			for (ov = VT_front; ov != vid; ov = vp->next) {
				vp = &VT_array[ov];
				getbegyx(vp->win, sr2, sc2);
				getmaxyx(vp->win, r2, c2);
				if (_vt_overlap(sr1, r1, sr2, r2) && _vt_overlap(sc1, c1, sc2, c2))
					vp->flags |= VT_BDIRTY;
			}
		v->flags &= ~VT_ANYDIRTY;
		}
        }
}

static void
vt_scroll_arrow(v, active_flag)
register struct vt	*v;
int active_flag;
{
	int	r;
	int	c;
	int	colattr;

	getmaxyx(v->win, r, c);
	wmove(v->win, r - 1, c - 4);
	if (active_flag == TRUE)
		colattr = ACTIVE_BORD_PAIR;
	else
		colattr = INACTIVE_BORD_PAIR;
	wattrset(v->win, COL_ATTR(A_NORMAL, colattr));
	if (v->flags & VT_UPSARROW)
		waddch(v->win, ACS_UARROW);
	else
		waddch(v->win, ACS_HLINE);
	if (v->flags & VT_DNSARROW)
		waddch(v->win, ACS_DARROW);
	else
		waddch(v->win, ACS_HLINE);
	wattrset(v->win, COL_ATTR(A_NORMAL, WINDOW_PAIR));
}

static void
vt_page_arrow(v, active_flag)
register struct vt	*v;
int active_flag;
{
	int	row, col;
	int	colattr;

	getmaxyx(v->win, row, col);
	if (row < 5)
		return;	     /* frame too small */
	if (active_flag) {
		if (!Pair_set[ACTIVE_SCROLL_PAIR] && Pair_set[ACTIVE_TITLE_PAIR])
			colattr = ACTIVE_TITLE_PAIR;
		else
			colattr = ACTIVE_SCROLL_PAIR;
		wattrset(v->win, COL_ATTR(Attr_highlight, colattr));
	}
	else {
		if (!Pair_set[INACTIVE_SCROLL_PAIR] && Pair_set[INACTIVE_TITLE_PAIR])
			colattr = INACTIVE_TITLE_PAIR;
		else
			colattr = INACTIVE_SCROLL_PAIR;
		wattrset(v->win, COL_ATTR(Attr_hide, colattr));
	}
	wmove(v->win, (row /= 2) - 1, col - 1);
	if (v->flags & VT_UPPARROW)
		waddch(v->win, ACS_UARROW);
	else
		waddch(v->win, ' ');
	wmove(v->win, row, col - 1);
	waddch(v->win, ' ');
	wmove(v->win, row + 1, col - 1);
	if (v->flags & VT_DNPARROW)
		waddch(v->win, ACS_DARROW);
	else
		waddch(v->win, ' ');
	wattrset(v->win, COL_ATTR(A_NORMAL, WINDOW_PAIR));
}

static void
vt_title(v, active_flag)
register struct vt	*v;
int	active_flag;
{
	register char	*s;
	int	c;
	int	dummy;
	int	bl;
	int	const_cols;

	if ((s = v->title) == NULL)
		s = nil;
	getmaxyx(v->win, dummy, c);

	/*
	 * const_cols is # of columns taken up by corners and by number 
	 * displayed on title line
	 */
	if (v->number > 0)
		const_cols = 5;
	else
		const_cols = 2;
	bl = (c - const_cols) / 2 - (strlen(v->title) + 1) / 2;
	if (bl < 0)
		bl = 0;
	c -= bl + const_cols;
	if (active_flag)
		wattrset(v->win, COL_ATTR(Attr_highlight, ACTIVE_TITLE_PAIR));
	else
		wattrset(v->win, COL_ATTR(Attr_hide, INACTIVE_TITLE_PAIR));
	wmove(v->win, 0, 1);
	if (v->number > 0)
/* abs: changed wprintw to wprintf in following 2 calls */
		wprintw(v->win, "%2d %*s%-*.*s", v->number, bl, "", c, c, s);
	else
		wprintw(v->win, "%*s%-*.*s", bl, "", c, c, s);
	wattrset(v->win, COL_ATTR(A_NORMAL, WINDOW_PAIR));
}
