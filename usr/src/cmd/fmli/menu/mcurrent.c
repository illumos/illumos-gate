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

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include	<stdio.h>
#include	<curses.h>
#include	"wish.h"
#include	"menu.h"
#include	"menudefs.h"
#include	"vtdefs.h"
#include	"attrs.h"
#include	"ctl.h"
#include	"color_pair.h"
#include	"sizes.h"

#define menu_pos(m, i, r, c, dr, dc)	((m->ncols > 1) ? (dc = i / r, dr = i % r) : (dc = 0, dr = i - m->topline))
#define NULLSTR	""

menu_id	MNU_curid = -1;
void	menu_index();

int
menu_current(mid)
menu_id	mid;
{
	register struct menu	*m;
	struct menu_line men;

	m = &MNU_array[mid];
	vt_current(m->vid);
	menu_index(m, m->index, m->hcols);
	/*
	 * This code determines the first menu item reached
	 * when the menu is first drawn.
	 *
	 * Do not match inactive menu items.
	 */
	men = (*m->disp)(m->index, m->arg);
	while (men.flags & MENU_INACT) {
		if (m->index < m->number - 1) {
			menu_index(m, m->index + 1, MENU_ALL);
			men = (*m->disp)(m->index, m->arg);
		}
		else {
			menu_index(m, 0, MENU_ALL);
			men = (*m->disp)(m->index, m->arg);
		}
	 }
	MNU_curid = mid;
	return SUCCESS;
}

int
menu_noncurrent()
{
	register struct menu	*m;

	if (MNU_curid < 0)
		return FAIL;
	m = &MNU_array[MNU_curid];
	menu_index(m, m->index, -1);
	m->hcols = MENU_ALL;
	_menu_cleanup();
	MNU_curid = -1;
	return SUCCESS;
}

void
menu_index(m, newindex, hcols)
register struct menu	*m;
int	newindex;
int	hcols;
{
	register int	col;
	register int	line;
	int	cwidth;
	int	huse;
	int	duse;
	int	destrow;
	int	destcol;
	int	rows;
	int	cols;
	int	scol;
	int	sind;
	struct menu_line	ml;
	static void	menu_show();

	vt_ctl(m->vid, CTGETSIZ, &rows, &cols);
	huse = min(m->hwidth, cwidth = (cols - 1) / m->ncols);
	huse = min(huse, cols - 2);
	if (m->dwidth)
		duse = max(0, cwidth - huse - 3);
	else
		duse = 0;
	/* remove old indicator (if any) */
	if (m->hcols >= 0 && m->index != newindex && m->index >= 0) {
		menu_pos(m, m->index, rows, cols, destrow, destcol);
		ml = (*m->disp)(m->index, m->arg);
		wgo(destrow, destcol * cwidth);
		menu_show(m, &ml, huse, duse, 0);
	}
	m->index = newindex;
	menu_pos(m, m->index, rows, cols, destrow, destcol);
	if ((m->flags & MENU_DIRTY) || destrow < -1 || destrow > rows) {
		/* desired index is far away - redraw menu with it in center */
		wgo(0, 0);
		wclrwin();
		m->topline = min(m->number - rows, m->index - rows / 2);
		if (m->ncols > 1 || m->index < (rows / 2))
			m->topline = 0;
		scol = 0;
		sind = m->topline;
		for (col = 0; col < m->ncols; col++) {
			for (line = 0; line < rows; line++) {
				ml = (*m->disp)(line + sind, m->arg);
				if (ml.highlight == NULL)
					break;
				wgo(line, scol);
				menu_show(m, &ml, huse, duse, 0);
			}
			scol += cwidth;
			sind += rows;
		}
		m->flags &= ~MENU_DIRTY;
		menu_pos(m, m->index, rows, cols, destrow, destcol);
	}
	else if (destrow == rows) {
		wscrollwin(1);
		m->topline++;
		destrow--;
	}
	else if (destrow == -1) {
		wscrollwin(-1);
		m->topline--;
		destrow++;
	}
	if (m->index >= 0) {
		ml = (*m->disp)(m->index, m->arg);
		wgo(destrow, destcol * cwidth);
		menu_show(m, &ml, huse, duse, hcols);
		m->hcols = hcols;
	}
	/* update arrows */
	if (m->ncols == 1) {
		line = 0;
		if (m->topline)
			line |= VT_UPPARROW;
		if (m->topline + rows < m->number)
			line |= VT_DNPARROW;
		vt_ctl(m->vid, CTSETPARROWS, line);
	}
}

static void
menu_show(m, ml, len1, len2, high)
register struct menu	*m;
register struct menu_line	*ml;
int	len1;
register int	len2;
int	high;
{
	register char	*s, ch;
	chtype theattr;
	register int	tot;
	int	r = 0;
	int	c = 0;
	int     vt_width, vt_height, row, col;
	
	vt_ctl(m->vid, CTGETPOS, &row, &col);
	if (ml->flags & MENU_MRK)
		ch = '*';
	else
		ch = (high ? MENU_MARKER : ' ');   /* really MENU_SELECTOR */
	wputchar(ch, Attr_normal, NULL);
	s = ml->highlight;
	if (s == NULL)
		s = NULLSTR;
	/* 
	 *  If a menu item is inactive, set the attributes to dim.
	 */
	if (ml->flags & MENU_INACT)
		theattr = A_DIM;
	else
		theattr = Attr_normal;
	tot = min(len1, strlen(s));
	if (high > 0) {
		vt_ctl(m->vid, CTSETATTR, Attr_select, BAR_PAIR);
		r = min(high, tot);
		for ( ; r > 0; r--, tot--, len1--)
			wputchar(*s++, theattr, NULL);
		vt_ctl(m->vid, CTGETPOS, &r, &c);
		vt_ctl(m->vid, CTSETATTR, Attr_normal, WINDOW_PAIR);
	}
	for ( ; tot-- > 0; len1--)
		wputchar(*s++, theattr, NULL);
	vt_ctl(m->vid, CTSETATTR, Attr_normal, WINDOW_PAIR);
	while (len1-- > 0)
		wputchar(' ', Attr_normal, NULL);
	if (m->flags & MENU_TRUNC)
	{
	    vt_ctl(m->vid, CTGETSIZ, &vt_height, &vt_width);
	    wgo(row, vt_width - LEN_TRUNC_STR -1);
	    winputs(TRUNCATE_STR, NULL);
	    len2 -= LEN_TRUNC_STR;
	}
	else
	{
	    s = ml->description;
	    if (s == NULL)
		s = NULLSTR;
	    if (s && len2 > 0) {
		winputs(" - ", NULL);
		for (tot = min(len2, strlen(s)); tot > 0; tot--, len2--)
		    wputchar(*s++, Attr_normal, NULL);
	    }
	}
	while (len2-- > 0)
	    wputchar(' ', Attr_normal, NULL);
	if (high)
	    wgo(r, c);
}


/* 
 * returns the "translated" menu item name (lininfo) or the
 * actual menu item name if the translated name is not provided.
 */
char *
menu_list(m, i)
struct menu	*m;
int i;
{
	struct menu_line ml;

	ml = (*m->disp)(i, m->arg);
	if (!(ml.flags & MENU_MRK))
		return(NULL);
	if (ml.lininfo && *(ml.lininfo) != '\0')
		return(ml.lininfo);
	else
		return(ml.highlight);
}
