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

void fixundo(void);

/*
 * This file defines the operation sequences which interface the
 * logical changes to the file buffer with the internal and external
 * display representations.
 */

/*
 * Undo.
 *
 * Undo is accomplished in two ways.  We often for small changes in the
 * current line know how (in terms of a change operator) how the change
 * occurred.  Thus on an intelligent terminal we can undo the operation
 * by another such operation, using insert and delete character
 * stuff.  The pointers vU[AD][12] index the buffer vutmp when this
 * is possible and provide the necessary information.
 *
 * The other case is that the change involved multiple lines or that
 * we have moved away from the line or forgotten how the change was
 * accomplished.  In this case we do a redisplay and hope that the
 * low level optimization routines (which don't look for winning
 * via insert/delete character) will not lose too badly.
 */
unsigned char	*vUA1, *vUA2;
unsigned char	*vUD1, *vUD2;

void
vUndo(void)
{

	/*
	 * Avoid UU which clobbers ability to do u.
	 */
	if (vundkind == VNONE || vundkind == VCAPU || vUNDdot != dot) {
		(void) beep();
		return;
	}
	CP(vutmp, linebuf);
	vUD1 = linebuf; vUD2 = strend(linebuf);
	putmk1(dot, vUNDsav);
	getDOT();
	vUA1 = linebuf; vUA2 = strend(linebuf);
	vundkind = VCAPU;
	if (state == ONEOPEN || state == HARDOPEN) {
		vjumpto(dot, vUNDcurs, 0);
		return;
	}
	vdirty(vcline, 1);
	if(MB_CUR_MAX > 1)
		rewrite = _ON;
	vsyncCL();
	if(MB_CUR_MAX > 1)
		rewrite = _OFF;
	cursor = linebuf;
	vfixcurs();
}

void
vundo(show)
bool show;	/* if true update the screen */
{
	int cnt;
	line *addr;
	unsigned char *cp;
	unsigned char temp[LBSIZE];
	bool savenote;
	int (*OO)();
	short oldhold = hold;
	unsigned multic[MULTI_BYTE_MAX];
	int length;
	wchar_t wchar;

	switch (vundkind) {

	case VMANYINS:
		wcursor = 0;
		addr1 = undap1;
		addr2 = undap2 - 1;
		vsave();
		(void) YANKreg('1');
		notecnt = 0;
		/* FALLTHROUGH */

	case VMANY:
	case VMCHNG:
		vsave();
		addr = dot - vcline;
		notecnt = 1;
		if (undkind == UNDPUT && undap1 == undap2) {
			(void) beep();
			break;
		}
		/*
		 * Undo() call below basically replaces undap1 to undap2-1
		 * with dol through unddol-1.  Hack screen image to
		 * reflect this replacement.
		 */
		if (show)
			if (undkind == UNDMOVE)
				vdirty(0, lines);
			else
				vreplace(undap1 - addr, undap2 - undap1,
				    undkind == UNDPUT ? 0 : unddol - dol);
		savenote = notecnt;
		undo(1);
		if (show && (vundkind != VMCHNG || addr != dot))
			killU();
		vundkind = VMANY;
		cnt = dot - addr;
		if (cnt < 0 || cnt > vcnt || state != VISUAL) {
			if (show)
				vjumpto(dot, (unsigned char *)NOSTR, '.');
			break;
		}
		if (!savenote)
			notecnt = 0;
		if (show) {
			vcline = cnt;
			if(MB_CUR_MAX > 1)
				rewrite = _ON;
			vrepaint(vmcurs);
			if(MB_CUR_MAX > 1)
				rewrite = _OFF;
		}
		vmcurs = 0;
		break;

	case VCHNG:
	case VCAPU:
		vundkind = VCHNG;
		strcpy(temp, vutmp);
		strcpy(vutmp, linebuf);
		doomed = lcolumn(vUA2) - lcolumn(vUA1);
		strcLIN(temp);
		cp = vUA1; vUA1 = vUD1; vUD1 = cp;
		cp = vUA2; vUA2 = vUD2; vUD2 = cp;
		if (!show)
			break;
		cursor = vUD1;
		if (state == HARDOPEN) {
			doomed = 0;
			vsave();
			vopen(dot, WBOT);
			vnline(cursor);
			break;
		}
		/*
		 * Pseudo insert command.
		 */
		vcursat(cursor);
		OO = Outchar; Outchar = vinschar; hold |= HOLDQIK;
		vprepins();
		temp[vUA2 - linebuf] = 0;
		for (cp = &temp[vUA1 - linebuf]; *cp;) {
			length = mbtowc(&wchar, (char *)cp, MULTI_BYTE_MAX);
			if(length < 0) {
				putoctal = 1;
				putchar(*cp++);
				putoctal = 0;
			} else {
				putchar(wchar);
				cp += length;
			}
		}
		Outchar = OO; hold = oldhold;
		endim();
		physdc(cindent(), cindent() + doomed);
		doomed = 0;
		vdirty(vcline, 1);
		if(MB_CUR_MAX > 1)
			rewrite = _ON;
		vsyncCL();
		if(MB_CUR_MAX > 1)
			rewrite = _OFF;
		if (cursor > linebuf && cursor >= strend(linebuf))
			cursor = lastchr(linebuf, cursor);
		vfixcurs();
		break;

	case VNONE:
		(void) beep();
		break;
	}
}

/*
 * Routine to handle a change inside a macro.
 * Fromvis is true if we were called from a visual command (as
 * opposed to an ex command).  This has nothing to do with being
 * in open/visual mode as :s/foo/bar is not fromvis.
 */
void
vmacchng(fromvis)
bool fromvis;
{
	line *savedot, *savedol;
	unsigned char *savecursor;
	unsigned char savelb[LBSIZE];
	int nlines, more;
	line *a1, *a2;
	unsigned char ch;	/* DEBUG */
	int copyw(), copywR();

	if (!inopen)
		return;
	if (!vmacp)
		vch_mac = VC_NOTINMAC;
#ifdef UNDOTRACE
	if (trace)
		fprintf(trace, "vmacchng, vch_mac=%d, linebuf='%s', *dot=%o\n", vch_mac, linebuf, *dot);
#endif
	if (vmacp && fromvis)
		vsave();
#ifdef UNDOTRACE
	if (trace)
		fprintf(trace, "after vsave, linebuf='%s', *dot=%o\n", linebuf, *dot);
#endif
	switch(vch_mac) {
	case VC_NOCHANGE:
		vch_mac = VC_ONECHANGE;
		break;
	case VC_ONECHANGE:
		/* Save current state somewhere */
#ifdef UNDOTRACE
		vudump("before vmacchng hairy case");
#endif
		savedot = dot; savedol = dol; savecursor = cursor;
		CP(savelb, linebuf);
		nlines = dol - zero;
		while ((line *) endcore - truedol < nlines)
			if (morelines() < 0)
				return;	/* or could be fatal error */
		copyw(truedol+1, zero+1, nlines);
		truedol += nlines;

#ifdef UNDOTRACE
		visdump("before vundo");
#endif
		/* Restore state as it was at beginning of macro */
		vundo(0);
#ifdef UNDOTRACE
		visdump("after vundo");
		vudump("after vundo");
#endif

		/* Do the saveall we should have done then */
		saveall();
#ifdef UNDOTRACE
		vudump("after saveall");
#endif

		/* Restore current state from where saved */
		more = savedol - dol; /* amount we shift everything by */
		if (more)
			(*(more>0 ? copywR : copyw))(savedol+1, dol+1, truedol-dol);
		unddol += more; truedol += more; undap2 += more;

		truedol -= nlines;
		copyw(zero+1, truedol+1, nlines);
		dot = savedot; dol = savedol ; cursor = savecursor;
		CP(linebuf, savelb);
		vch_mac = VC_MANYCHANGE;

		/* Arrange that no further undo saving happens within macro */
		otchng = tchng;	/* Copied this line blindly - bug? */
		inopen = -1;	/* no need to save since it had to be 1 or -1 before */
		vundkind = VMANY;
#ifdef UNDOTRACE
		vudump("after vmacchng");
#endif
		break;
	case VC_NOTINMAC:
	case VC_MANYCHANGE:
		/* Nothing to do for various reasons. */
		break;
	}
}

/*
 * Initialize undo information before an append.
 */
void
vnoapp(void)
{
	vUD1 = vUD2 = cursor;
	/*
	 * XPG6 assertion 273: Set vmcurs so that undo positions the
	 * cursor column correctly when we've moved off the initial
	 * line that was changed with the A, a, i, and R commands,
	 * eg: when G has moved us off the line, or when a
	 * multi-line change was done.
	 */
	if (lastcmd[0] == 'A' || lastcmd[0] == 'a' || lastcmd[0] == 'i' ||
	    lastcmd[0] == 'R') {
		vmcurs = cursor;
	}
}

/*
 * All the rest of the motion sequences have one or more
 * cases to deal with.  In the case wdot == 0, operation
 * is totally within current line, from cursor to wcursor.
 * If wdot is given, but wcursor is 0, then operation affects
 * the inclusive line range.  The hardest case is when both wdot
 * and wcursor are given, then operation affects from line dot at
 * cursor to line wdot at wcursor.
 */

/*
 * Move is simple, except for moving onto new lines in hardcopy open mode.
 */
int
vmove(void)
{
	int cnt;

	if (wdot) {
		if (wdot < one || wdot > dol) {
			(void) beep();
			return (0);
		}
		cnt = wdot - dot;
		wdot = NOLINE;
		if (cnt)
			killU();
		vupdown(cnt, wcursor);
		return (0);
	}

	/*
	 * When we move onto a new line, save information for U undo.
	 */
	if (vUNDdot != dot) {
		vUNDsav = *dot;
		vUNDcurs = wcursor;
		vUNDdot = dot;
	}

	/*
	 * In hardcopy open, type characters to left of cursor
	 * on new line, or back cursor up if its to left of where we are.
	 * In any case if the current line is ``rubbled'' i.e. has trashy
	 * looking overstrikes on it or \'s from deletes, we reprint
	 * so it is more comprehensible (and also because we can't work
	 * if we let it get more out of sync since column() won't work right.
	 */
	if (state == HARDOPEN) {
		unsigned char *cp;
		if (rubble) {
			int c;
			int oldhold = hold;

			sethard();
			cp = wcursor;
			c = *cp;
			*cp = 0;
			hold |= HOLDDOL;
			(void) vreopen(WTOP, lineDOT(), vcline);
			hold = oldhold;
			*cp = c;
		} else if (wcursor > cursor) {
			int length;
			char multic[MULTI_BYTE_MAX];
			wchar_t wchar;
			vfixcurs();
			for (cp = cursor; *cp && cp < wcursor;) {
				length = mbtowc(&wchar, (char *)cp, MULTI_BYTE_MAX);
				if(length == 0)	
					putchar(' ');
				else if(length < 0) {
					putoctal = 1;
					putchar(*cp++);
					putoctal = 0;
				} else {
					cp += length;
					putchar(wchar);
				}
			}
		}
	}
	vsetcurs(wcursor);
	return (0);
}

/*
 * Delete operator.
 *
 * Hard case of deleting a range where both wcursor and wdot
 * are specified is treated as a special case of change and handled
 * by vchange (although vchange may pass it back if it degenerates
 * to a full line range delete.)
 */
int
vdelete(unsigned char c)
{
	unsigned char *cp;
	int i;

	if (wdot) {
		if (wcursor) {
			(void) vchange('d');
			return (0);
		}
		if ((i = xdw()) < 0)
			return (0);
		if (state != VISUAL) {
			vgoto(LINE(0), 0);
			(void) vputchar('@');
		}
		wdot = dot;
		vremote(i, delete, 0);
		notenam = (unsigned char *)"delete";
		DEL[0] = 0;
		killU();
		vreplace(vcline, i, 0);
		if (wdot > dol)
			vcline--;
		vrepaint(NOSTR);
		return (0);
	}
	if (wcursor < linebuf)
		wcursor = linebuf;
	if (cursor == wcursor) {
		(void) beep();
		return (0);
	}
	i = vdcMID();
	cp = cursor;
	setDEL();
	CP(cp, wcursor);
	if (cp > linebuf && (cp[0] == 0 || c == '#'))
		cp = lastchr(linebuf, cp);
	if (state == HARDOPEN) {
		bleep(i, cp);
		cursor = cp;
		return (0);
	}
	physdc(lcolumn(cursor), i);
	DEPTH(vcline) = 0;
	if(MB_CUR_MAX > 1)
		rewrite = _ON;
	(void) vreopen(LINE(vcline), lineDOT(), vcline);
	if(MB_CUR_MAX > 1)
		rewrite = _OFF;
	vsyncCL();
	vsetcurs(cp);
	return (0);
}

/*
 * Change operator.
 *
 * In a single line we mark the end of the changed area with '$'.
 * On multiple whole lines, we clear the lines first.
 * Across lines with both wcursor and wdot given, we delete
 * and sync then append (but one operation for undo).
 */
int
vchange(unsigned char c)
{
	unsigned char *cp;
	int i, ind, cnt;
	line *addr;

	if (wdot) {
		/*
		 * Change/delete of lines or across line boundaries.
		 */
		if ((cnt = xdw()) < 0)
			return (0);
		getDOT();
		if (wcursor && cnt == 1) {
			/*
			 * Not really.
			 */
			wdot = 0;
			if (c == 'd') {
				(void) vdelete(c);
				return (0);
			}
			goto smallchange;
		}
		if (cursor && wcursor) {
			/*
			 * Across line boundaries, but not
			 * necessarily whole lines.
			 * Construct what will be left.
			 */
			*cursor = 0;
			strcpy(genbuf, linebuf);
			getaline(*wdot);
			if (strlen(genbuf) + strlen(wcursor) > LBSIZE - 2) {
				getDOT();
				(void) beep();
				return (0);
			}
			strcat(genbuf, wcursor);
			if (c == 'd' && *vpastwh(genbuf) == 0) {
				/*
				 * Although this is a delete
				 * spanning line boundaries, what
				 * would be left is all white space,
				 * so take it all away.
				 */
				wcursor = 0;
				getDOT();
				op = 0;
				notpart(lastreg);
				notpart('1');
				(void) vdelete(c);
				return (0);
			}
			ind = -1;
		} else if (c == 'd' && wcursor == 0) {
			(void) vdelete(c);
			return (0);
		} else
			/*
			 * We are just substituting text for whole lines,
			 * so determine the first autoindent.
			 */
			if (value(vi_LISP) && value(vi_AUTOINDENT))
				ind = lindent(dot);
			else
				ind = whitecnt(linebuf);
		i = vcline >= 0 ? LINE(vcline) : WTOP;

		/*
		 * Delete the lines from the buffer,
		 * and remember how the partial stuff came about in
		 * case we are told to put.
		 */
		addr = dot;
		vremote(cnt, delete, 0);
		setpk();
		notenam = (unsigned char *)"delete";
		if (c != 'd')
			notenam = (unsigned char *)"change";
		/*
		 * If DEL[0] were nonzero, put would put it back
		 * rather than the deleted lines.
		 */
		DEL[0] = 0;
		if (cnt > 1)
			killU();

		/*
		 * Now hack the screen image coordination.
		 */
		vreplace(vcline, cnt, 0);
		wdot = NOLINE;
		noteit(0);
		vcline--;
		if (addr <= dol)
			dot--;

		/*
		 * If this is a across line delete/change,
		 * cursor stays where it is; just splice together the pieces
		 * of the new line.  Otherwise generate a autoindent
		 * after a S command.
		 */
		if (ind >= 0) {
			/*
			 * XPG6 assertion 273: Set vmcurs so that cursor
			 * column will be set by undo.
			 */
			fixundo();
			*genindent(ind) = 0;
			vdoappend(genbuf);
		} else {
			vmcurs = cursor;
			strcLIN(genbuf);
			vdoappend(linebuf);
		}

		/*
		 * Indicate a change on hardcopies by
		 * erasing the current line.
		 */
		if (c != 'd' && state != VISUAL && state != HARDOPEN) {
			int oldhold = hold;

			hold |= HOLDAT, vclrlin(i, dot), hold = oldhold;
		}

		/*
		 * Open the line (logically) on the screen, and 
		 * update the screen tail.  Unless we are really a delete
		 * go off and gather up inserted characters.
		 */
		vcline++;
		if (vcline < 0)
			vcline = 0;
		vopen(dot, i);
		vsyncCL();
		noteit(1);
		if (c != 'd') {
			if (ind >= 0) {
				cursor = linebuf;
				/*
				 * XPG6 assertion 273: Set vmcurs so that
				 * cursor column will be set by undo.  When
				 * undo is preceded by 'S' or 'O' command,
				 * white space isn't skipped in vnline(vmcurs).
				 */
				fixundo();
				linebuf[0] = 0;
				vfixcurs();
			} else {
				ind = 0;
				/*
				 * XPG6 assertion 273: Set vmcurs so that
				 * cursor column will be set by undo.
				 */
				fixundo();
				vcursat(cursor);
			}
			vappend('x', 1, ind);
			return (0);
		}
		if (*cursor == 0 && cursor > linebuf)
			cursor = lastchr(linebuf, cursor);
		vrepaint(cursor);
		return (0);
	}

smallchange:
	/*
	 * The rest of this is just low level hacking on changes
	 * of small numbers of characters.
	 */
	if (wcursor < linebuf)
		wcursor = linebuf;
	if (cursor == wcursor) {
		(void) beep();
		return (0);
	}
	i = vdcMID();
	cp = cursor;
	if (state != HARDOPEN)
		vfixcurs();

	/*
	 * Put out the \\'s indicating changed text in hardcopy,
	 * or mark the end of the change with $ if not hardcopy.
	 */
	if (state == HARDOPEN) 
		bleep(i, cp);
	else {
		vcursbef(wcursor);
		putchar('$');
		i = cindent();
	}

	/*
	 * Remember the deleted text for possible put,
	 * and then prepare and execute the input portion of the change.
	 */
	cursor = cp;
	setDEL();
	CP(cursor, wcursor);
	/*
	 * XPG6 assertion 273: Set vmcurs so that cursor column will be
	 * set by undo.
	 */
	fixundo();
	if (state != HARDOPEN) {
		/* place cursor at beginning of changing text */
		vgotoCL(lcolumn(cp));
		doomed = i - cindent();
	} else {
/*
		sethard();
		wcursor = cursor;
		cursor = linebuf;
		vgoto(outline, value(vi_NUMBER) << 3);
		vmove();
*/
		doomed = 0;
	}
	prepapp();
	vappend('c', 1, 0);
	return (0);
}

/*
 * Open new lines.
 */
void
voOpen(int c, int cnt)
{
	int ind = 0, i;
	short oldhold = hold;

	vsave();
	setLAST();
	if (value(vi_AUTOINDENT))
		ind = whitecnt(linebuf);
	if (c == 'O') {
		vcline--;
		dot--;
		if (dot > zero)
			getDOT();
	}
	if (value(vi_AUTOINDENT)) {
		if (value(vi_LISP))
			ind = lindent(dot + 1);
	}
	killU();
	prepapp();
	if (FIXUNDO)
		vundkind = VMANY;
	if (state != VISUAL)
		c = WBOT + 1;
	else {
		c = vcline < 0 ? WTOP - cnt : LINE(vcline) + DEPTH(vcline);
		if (c < ZERO)
			c = ZERO;
		i = LINE(vcline + 1) - c;
		if (i < cnt && c <= WBOT && (!insert_line || !delete_line))
			vinslin(c, cnt - i, vcline);
	}
	*genindent(ind) = 0;
	vdoappend(genbuf);
	vcline++;
	oldhold = hold;
	hold |= HOLDROL;
	vopen(dot, c);
	hold = oldhold;
	if (value(vi_SLOWOPEN))
		/*
		 * Oh, so lazy!
		 */
		vscrap();
	else
		vsync1(LINE(vcline));
	cursor = linebuf;
	/*
	 * XPG6 assertion 273: Set vmcurs so that cursor column will be
	 * set by undo.  For undo preceded by 'o' command, white space
	 * isn't skipped in vnline(vmcurs).
	 */
	fixundo();
	linebuf[0] = 0;
	vappend('o', cnt, ind);
}

/*
 * > < and = shift operators.
 *
 * Note that =, which aligns lisp, is just a ragged sort of shift,
 * since it never distributes text between lines.
 */
unsigned char	vshnam[2] = { 'x', 0 };

int
vshftop(void)
{
	line *addr;
	int cnt;

	if ((cnt = xdw()) < 0)
		return (0);
	addr = dot;
	vremote(cnt, vshift, 0);
	vshnam[0] = op;
	notenam = vshnam;
	dot = addr;
	vreplace(vcline, cnt, cnt);
	if (state == HARDOPEN)
		vcnt = 0;
	vrepaint(NOSTR);
	return (0);
}

/*
 * !.
 *
 * Filter portions of the buffer through unix commands.
 */
int
vfilter(void)
{
	line *addr;
	int cnt;
	unsigned char *oglobp;
	short d;

	if ((cnt = xdw()) < 0)
		return (0);
	if (vglobp)
		vglobp = (unsigned char *)uxb;
	if (readecho('!'))
		return (0);
	oglobp = globp; globp = genbuf + 1;
	d = peekc; ungetchar(0);
	CATCH
		fixech();
		unix0(0, 0);
	ONERR
		splitw = 0;
		ungetchar(d);
		vrepaint(cursor);
		globp = oglobp;
		return (0);
	ENDCATCH
	ungetchar(d); globp = oglobp;
	addr = dot;
	CATCH
		vgoto(WECHO, 0); flusho();
		vremote(cnt, vi_filter, 2);
	ONERR
		vdirty(0, lines);
	ENDCATCH
	if (dot == zero && dol > zero)
		dot = one;
	splitw = 0;
	notenam = (unsigned char *)"";
	/*
	 * BUG: we shouldn't be depending on what undap2 and undap1 are,
	 * since we may be inside a macro.  What's really wanted is the
	 * number of lines we read from the filter.  However, the mistake
	 * will be an overestimate so it only results in extra work,
	 * it shouldn't cause any real mess-ups.
	 */
	vreplace(vcline, cnt, undap2 - undap1);
	dot = addr;
	if (dot > dol) {
		dot--;
		vcline--;
	}
	vrepaint(NOSTR);
	return (0);
}

/*
 * Xdw exchanges dot and wdot if appropriate and also checks
 * that wdot is reasonable.  Its name comes from
 *	xchange dotand wdot
 */
int
xdw(void)
{
	unsigned char *cp;
	int cnt;
/*
	register int notp = 0;
 */

	if (wdot == NOLINE || wdot < one || wdot > dol) {
		(void) beep();
		return (-1);
	}
	vsave();
	setLAST();
	if (dot > wdot || (dot == wdot && wcursor != 0 && cursor > wcursor)) {
		line *addr;

		vcline -= dot - wdot;
		addr = dot; dot = wdot; wdot = addr;
		cp = cursor; cursor = wcursor; wcursor = cp;
	}
	/*
	 * If a region is specified but wcursor is at the beginning
	 * of the last line, then we move it to be the end of the
	 * previous line (actually off the end).
	 */
	if (cursor && wcursor == linebuf && wdot > dot) {
		wdot--;
		getDOT();
		if (vpastwh(linebuf) >= cursor)
			wcursor = 0;
		else {
			getaline(*wdot);
			wcursor = strend(linebuf);
			getDOT();
		}
		/*
		 * Should prepare in caller for possible dot == wdot.
		 */
	}
	cnt = wdot - dot + 1;
	if (vreg) {
		vremote(cnt, YANKreg, vreg);
/*
		if (notp)
			notpart(vreg);
 */
	}

	/*
	 * Kill buffer code.  If delete operator is c or d, then save
	 * the region in numbered buffers.
	 *
	 * BUG:			This may be somewhat inefficient due
	 *			to the way named buffer are implemented,
	 *			necessitating some optimization.
	 */
	vreg = 0;
	/* XPG6 assertion 194 and 264: use numeric buffers for 'C' and 'S' */
	if (any(op, (unsigned char *)"cdCS")) {
		vremote(cnt, YANKreg, '1');
/*
		if (notp)
			notpart('1');
 */
	}
	return (cnt);
}

/*
 * Routine for vremote to call to implement shifts.
 */
int
vshift(void)
{

	shift(op, 1);
	return (0);
}

/*
 * Replace a single character with the next input character.
 * A funny kind of insert.
 */
void
vrep(int cnt)
{
	int i, c;
	unsigned char *endcurs;
	endcurs = cursor;
	/* point endcurs to last char entered */
	for(i = 1; i <= cnt; i++) {
		if(!*endcurs) {
			(void) beep();
			return;
		}
		endcurs = nextchr(endcurs);
	}
	i = lcolumn(endcurs);
	vcursat(cursor);
	doomed = i - cindent();
	/*
	 * TRANSLATION_NOTE
	 *	"r" is a terse mode message that corresponds to
	 *	"REPLACE 1 CHAR".
	 *	Translated message of "r" must be 1 character (not byte).
	 *	Or, just leave it.
	 */
	if(value(vi_TERSE))
		vshowmode(gettext("r"));
	else
		vshowmode(gettext("REPLACE 1 CHAR"));
	if (!vglobp) {
		/* get a key using getkey() */
		c = getesc();
		if (c == 0) {
			vshowmode("");
			vfixcurs();
			return;
		}
		ungetkey(c);
	}
	CP(vutmp, linebuf);
	if (FIXUNDO)
		vundkind = VCHNG;
	wcursor = endcurs;
	vUD1 = cursor; vUD2 = wcursor;
	CP(cursor, wcursor);
	/* before appending lines, set addr1 and undo information */
	prepapp();
	vappend('r', cnt, 0);
	*lastcp++ = INS[0];
	setLAST();
}

/*
 * Yank.
 *
 * Yanking to string registers occurs for free (essentially)
 * in the routine xdw().
 */
int
vyankit(void)
{
	int cnt;

	if (wdot) {
		if ((cnt = xdw()) < 0)
			return (0);
		vremote(cnt, yank, 0);
		setpk();
		notenam = (unsigned char *)"yank";
		if (FIXUNDO)
			vundkind = VNONE;
		DEL[0] = 0;
		wdot = NOLINE;
		if (notecnt <= vcnt - vcline && notecnt < value(vi_REPORT))
			notecnt = 0;
		vrepaint(cursor);
		return (0);
	} else {
		/*
		 * For one line y<motion> commands, eg. 2yw, save the
		 * command for a subsequent [count].
		 */
		setLAST();
	}
	takeout(DEL);
	return (0);

}

/*
 * Set pkill variables so a put can
 * know how to put back partial text.
 * This is necessary because undo needs the complete
 * line images to be saved, while a put wants to trim
 * the first and last lines.  The compromise
 * is for put to be more clever.
 */
void
setpk(void)
{

	if (wcursor) {
		pkill[0] = cursor;
		pkill[1] = wcursor;
	}
}

/*
 * XPG6 assertion 273 : If the command is C, c, o, R, S, or s, set vmcurs
 * so that the cursor column will be set by undo.
 */
void
fixundo(void)
{
	if (lastcmd[0] == 'C' || lastcmd[0] == 'c' || lastcmd[0] == 'o' ||
	    lastcmd[0] == 'R' || lastcmd[0] == 'S' || lastcmd[0] == 's') {
		vmcurs = cursor;
	}
}
