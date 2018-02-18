/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
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
 * Copyright (c) 1989, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


/* Copyright (c) 1981 Regents of the University of California */

#include "ex.h"
#include "ex_tty.h"
#include "ex_vis.h"

/*
 * Routines to adjust the window, showing specified lines
 * in certain positions on the screen, and scrolling in both
 * directions.  Code here is very dependent on mode (open versus visual).
 */

/*
 * Move in a nonlocal way to line addr.
 * If it isn't on screen put it in specified context.
 * New position for cursor is curs.
 * Like most routines here, we vsave().
 */
void
vmoveto(addr, curs, context)
	line *addr;
	unsigned char *curs;
	unsigned char context;
{

	markit(addr);
	vsave();
	vjumpto(addr, curs, context);
}

/*
 * Vjumpto is like vmoveto, but doesn't mark previous
 * context or save linebuf as current line.
 */
void
vjumpto(line *addr, unsigned char *curs, unsigned char context)
{

	noteit(0);
	if (context != 0)
		vcontext(addr, context);
	else
		vshow(addr, NOLINE);
	noteit(1);
	vnline(curs);
}

/*
 * Go up or down cnt (negative is up) to new position curs.
 */
void
vupdown(int cnt, unsigned char *curs)
{

	if (cnt > 0)
		vdown(cnt, 0, 0);
	else if (cnt < 0)
		vup(-cnt, 0, 0);
	if (vcnt == 0)
		vrepaint(curs);
	else
		vnline(curs);
}

/*
 * Go up cnt lines, afterwards preferring to be ind
 * logical lines from the top of the screen.
 * If scroll, then we MUST use a scroll.
 * Otherwise clear and redraw if motion is far.
 */
void
vup(int cnt, int ind, bool scroll)
{
	int i, tot;

	if (dot == one) {
		(void) beep();
		return;
	}
	vsave();
	i = lineDOT() - 1;
	if (cnt > i) {
		ind -= cnt - i;
		if (ind < 0)
			ind = 0;
		cnt = i;
	}
	if (!scroll && cnt <= vcline) {
		vshow(dot - cnt, NOLINE);
		return;
	}
	cnt -= vcline, dot -= vcline, vcline = 0;
	if (hold & HOLDWIG)
		goto contxt;
	if (state == VISUAL && !insert_line && !scroll_reverse &&
	    cnt <= WTOP - ZERO && vfit(dot - cnt, cnt) <= WTOP - ZERO)
		goto okr;
	tot = WECHO - WTOP;
	if (state != VISUAL || (!insert_line && !scroll_reverse) || (!scroll && (cnt > tot || vfit(dot - cnt, cnt) > tot / 3 + 1))) {
		if (ind > basWLINES / 2)
			ind = basWLINES / 3;
contxt:
		vcontext(dot + ind - cnt, '.');
		return;
	}
okr:
	vrollR(cnt);
	if (scroll) {
		vcline += ind, dot += ind;
		if (vcline >= vcnt)
			dot -= vcline - vcnt + 1, vcline = vcnt - 1;
		getDOT();
	}
}

/*
 * Like vup, but scrolling down.
 */
void
vdown(int cnt, int ind, bool scroll)
{
	int i, tot;

	if (dot == dol) {
		(void) beep();
		return;
	}
	vsave();
	i = dol - dot;
	if (cnt > i) {
		ind -= cnt - i;
		if (ind < 0)
			ind = 0;
		cnt = i;
	}
	i = vcnt - vcline - 1;
	if (!scroll && cnt <= i) {
		vshow(dot + cnt, NOLINE);
		return;
	}
	cnt -= i, dot += i, vcline += i;
	if (hold & HOLDWIG)
		goto dcontxt;
	if (!scroll) {
		tot = WECHO - WTOP;
		if (state != VISUAL || cnt - tot > 0 || vfit(dot, cnt) > tot / 3 + 1) {
dcontxt:
			vcontext(dot + cnt, '.');
			return;
		}
	}
	if (cnt > 0)
		vroll(cnt);
	if (state == VISUAL && scroll) {
		vcline -= ind, dot -= ind;
		if (vcline < 0)
			dot -= vcline, vcline = 0;
		getDOT();
	}
}

/*
 * Show line addr in context where on the screen.
 * Work here is in determining new top line implied by
 * this placement of line addr, since we always draw from the top.
 */
void
vcontext(line *addr, unsigned char where)
{
	line *top;

	getaline(*addr);
	if (state != VISUAL)
		top = addr;
	else switch (where) {

	case '^':
		addr = vback(addr, basWLINES - vdepth());
		getaline(*addr);
		/* FALLTHROUGH */

	case '-':
		top = vback(addr, basWLINES - vdepth());
		getaline(*addr);
		break;

	case '.':
		top = vback(addr, basWLINES / 2 - vdepth());
		getaline(*addr);
		break;

	default:
		top = addr;
		break;
	}
	if (state == ONEOPEN && LINE(0) == WBOT)
		vup1();
	vcnt = vcline = 0;
	vclean();
	if (state == CRTOPEN)
		vup1();
	vshow(addr, top);
}

/*
 * Get a clean line.  If we are in a hard open
 * we may be able to reuse the line we are on
 * if it is blank.  This is a real win.
 */
void
vclean(void)
{

	if (state != VISUAL && state != CRTOPEN) {
		destcol = 0;
		if (!ateopr())
			vup1();
		vcnt = 0;
	}
}

/*
 * Show line addr with the specified top line on the screen.
 * Top may be 0; in this case have vcontext compute the top
 * (and call us recursively).  Eventually, we clear the screen
 * (or its open mode equivalent) and redraw.
 */
void
vshow(line *addr, line *top)
{
#ifndef CBREAK
	bool fried = 0;
#endif
	int cnt = addr - dot;
	int i = vcline + cnt;
	short oldhold = hold;

	if (state != HARDOPEN && state != ONEOPEN && i >= 0 && i < vcnt) {
		dot = addr;
		getDOT();
		vcline = i;
		return;
	}
	if (state != VISUAL) {
		dot = addr;
		vopen(dot, WBOT);
		return;
	}
	if (top == 0) {
		vcontext(addr, '.');
		return;
	}
	dot = top;
#ifndef CBREAK
	if (vcookit(2))
		fried++, vcook();
#endif
	oldhold = hold;
	hold |= HOLDAT;
	vclear();
	vreset(0);
	vredraw(WTOP);
	/* error if vcline >= vcnt ! */
	vcline = addr - top;
	dot = addr;
	getDOT();
	hold = oldhold;
	vsync(LASTLINE);
#ifndef CBREAK
	if (fried)
		flusho(), vraw();
#endif
}

/*
 * reset the state.
 * If inecho then leave us at the beginning of the echo
 * area;  we are called this way in the middle of a :e escape
 * from visual, e.g.
 */
void
vreset(bool inecho)
{

	vcnt = vcline = 0;
	WTOP = basWTOP;
	WLINES = basWLINES;
	if (inecho)
		splitw = 1, vgoto(WECHO, 0);
}

/*
 * Starting from which line preceding tp uses almost (but not more
 * than) cnt physical lines?
 */
line *
vback(tp, cnt)
	int cnt;
	line *tp;
{
	int d;

	if (cnt > 0)
		for (; tp > one; tp--) {
			getaline(tp[-1]);
			d = vdepth();
			if (d > cnt)
				break;
			cnt -= d;
		}
	return (tp);
}

/*
 * How much scrolling will it take to roll cnt lines starting at tp?
 */
int
vfit(line *tp, int cnt)
{
	int j;

	j = 0;
	while (cnt > 0) {
		cnt--;
		getaline(tp[cnt]);
		j += vdepth();
	}
	if (tp > dot)
		j -= WBOT - LASTLINE;
	return (j);
}

/*
 * Roll cnt lines onto the screen.
 */
void
vroll(int cnt)
{
#ifndef CBREAK
	bool fried = 0;
#endif
	short oldhold = hold;

#ifdef ADEBUG
	if (trace)
		tfixnl(), fprintf(trace, "vroll(%d)\n", cnt);
#endif
	if (state != VISUAL)
		hold |= HOLDAT|HOLDROL;
	if (WBOT == WECHO) {
		vcnt = 0;
		if (state == ONEOPEN)
			vup1();
	}
#ifndef CBREAK
	if (vcookit(cnt))
		fried++, vcook();
#endif
	for (; cnt > 0 && Peekkey != ATTN; cnt--) {
		dot++, vcline++;
		vopen(dot, LASTLINE);
		vscrap();
	}
	hold = oldhold;
	if (state == HARDOPEN)
		sethard();
	vsyncCL();
#ifndef CBREAK
	if (fried)
		flusho(), vraw();
#endif
}

/*
 * Roll backwards (scroll up).
 */
void
vrollR(int cnt)
{
	bool fried = 0;
	short oldhold = hold;

#ifdef ADEBUG
	if (trace)
		tfixnl(), fprintf(trace, "vrollR(%d), dot=%d\n", cnt, lineDOT());
#endif
#ifndef CBREAK
	if (vcookit(cnt))
		fried++, vcook();
#endif
	if (WBOT == WECHO)
		vcnt = 0;
	heldech = 0;
	hold |= HOLDAT|HOLDECH;
	for (; cnt > 0 && Peekkey != ATTN; cnt--) {
		dot--;
		vopen(dot, WTOP);
		vscrap();
	}
	hold = oldhold;
	if (heldech)
		vclrech(0);
	vsync(LINE(vcnt-1));
#ifndef CBREAK
	if (fried)
		flusho(), vraw();
#endif
}

/*
 * Go into cooked mode (allow interrupts) during
 * a scroll if we are at less than 1200 baud and not
 * a 'vi' command, of if we are in a 'vi' command and the
 * scroll is more than 2 full screens.
 *
 * BUG:		An interrupt during a scroll in this way
 *		dumps to command mode.
 */
int
vcookit(int cnt)
{

	return (cnt > 1 && (ospeed < B1200 && !initev || cnt > lines * 2));
}

/*
 * Determine displayed depth of current line.
 */
int
vdepth(void)
{
	int d;

	d = (column(NOSTR) + WCOLS - 1 + (Putchar == listchar) + insert_null_glitch) / WCOLS;
#ifdef ADEBUG
	if (trace)
		tfixnl(), fprintf(trace, "vdepth returns %d\n", d == 0 ? 1 : d);
#endif
	return (d == 0 ? 1 : d);
}

/*
 * Move onto a new line, with cursor at position curs.
 */
void
vnline(unsigned char *curs)
{
	unsigned char *owcursor;
	int j;
	if (curs) {
		if(curs >= strend(linebuf)) {
			if(!*linebuf)
				wcursor = linebuf;
			else {
				wcursor = strend(linebuf);
				wcursor = lastchr(linebuf, wcursor);
			}
		} else {
			owcursor = wcursor = curs;
			j = wcursor - linebuf;
			for(wcursor = linebuf; wcursor - linebuf < j; ) {
				owcursor = wcursor;
				wcursor = nextchr(wcursor);
			}
			if(wcursor - linebuf > j)
				wcursor = owcursor;
		}
			
	} else if (vmoving)
		wcursor = vfindcol(vmovcol);
	else
		wcursor = vskipwh(linebuf);
	cursor = linebuf;
	(void) vmove();
}
