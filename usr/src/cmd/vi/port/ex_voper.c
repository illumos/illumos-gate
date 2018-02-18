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


/*
 * Copyright (c) 1981 Regents of the University of California
 */

#include "ex.h"
#include "ex_tty.h"
#include "ex_vis.h"
#include <regexpr.h>
#ifndef PRESUNEUC
#include <wctype.h>
/* Undef putchar/getchar if they're defined. */
#ifdef putchar
#undef putchar
#endif
#ifdef getchar
#undef getchar
#endif
#endif /* PRESUNEUC */

#ifdef PRESUNEUC
#define	blank()		isspace(wcursor[0])
#endif /* PRESUNEUC */
#define	forbid(a)	if (a) goto errlab;

unsigned char	vscandir[2] =	{ '/', 0 };

static int get_addr();

/*
 * Decode an operator/operand type command.
 * Eventually we switch to an operator subroutine in ex_vops.c.
 * The work here is setting up a function variable to point
 * to the routine we want, and manipulation of the variables
 * wcursor and wdot, which mark the other end of the affected
 * area.  If wdot is zero, then the current line is the other end,
 * and if wcursor is zero, then the first non-blank location of the
 * other line is implied.
 */
void
operate(int c, int cnt)
{
	wchar_t i;
	int (*moveop)(), (*deleteop)();
	int (*opf)();
	bool subop = 0;
	unsigned char *oglobp, *ocurs;
	line *addr;
	line *odot;
	int oc;
	static unsigned char lastFKND;
	static wchar_t lastFCHR;
	short d;
/* #ifdef PTR_ADDRESSES */
	int mouse_x;
	int mouse_y;
	int oline;
/* #endif PTR_ADDRESSES */

	moveop = vmove, deleteop = (int (*)())vdelete;
	wcursor = cursor;
	wdot = NOLINE;
	notecnt = 0;
	dir = 1;
	switch (c) {

	/*
	 * d		delete operator.
	 */
	case 'd':
		moveop = (int (*)())vdelete;
		deleteop = beep;
		break;

	/*
	 * s		substitute characters, like c\040, i.e. change space.
	 */
	case 's':
		ungetkey(' ');
		subop++;
		/* FALLTHROUGH */

	/*
	 * c		Change operator.
	 */
	case 'c':
		if (c == 'c' && workcmd[0] == 'C' || workcmd[0] == 'S')
			subop++;
		moveop = (int (*)())vchange;
		deleteop = beep;
		break;

	/*
	 * !		Filter through a UNIX command.
	 */
	case '!':
		moveop = vfilter;
		deleteop = beep;
		break;

	/*
	 * y		Yank operator.  Place specified text so that it
	 *		can be put back with p/P.  Also yanks to named buffers.
	 */
	case 'y':
		moveop = vyankit;
		deleteop = beep;
		break;

	/*
	 * =		Reformat operator (for LISP).
	 */
	case '=':
		forbid(!value(vi_LISP));
		/* FALLTHROUGH */

	/*
	 * >		Right shift operator.
	 * <		Left shift operator.
	 */
	case '<':
	case '>':
		moveop = vshftop;
		deleteop = beep;
		break;

	/*
	 * r		Replace character under cursor with single following
	 *		character.
	 */
	case 'r':
		vmacchng(1);
		vrep(cnt);
		return;

	default:
		goto nocount;
	}
	vmacchng(1);
	/*
	 * Had an operator, so accept another count.
	 * Multiply counts together.
	 */
	if (isdigit(peekkey()) && peekkey() != '0') {
		cnt *= vgetcnt();
		Xcnt = cnt;
		forbid(cnt <= 0);
	}

	/*
	 * Get next character, mapping it and saving as
	 * part of command for repeat.
	 */
	c = map(getesc(), arrows, 0);
	if (c == 0)
		return;
	if (!subop)
		*lastcp++ = c;
nocount:
	opf = moveop;
	switch (c) {

/* #ifdef PTR_ADDRESSES */
	/*
	 * ^X^_		Netty Mouse positioning hack
	 * ^X^]
	 */
	case CTRL('X'):
/*
 *	Read in mouse stuff
 */
		c = getkey();			/* ^_ or ^] */
		if ((c != CTRL('_')) && (c != (CTRL(']'))))
			break;
		getkey();			/* mouse button */
		mouse_x = get_addr() + 1;
		mouse_y = get_addr() + 1;
		if (mouse_y < WTOP)
			break;
		if (Pline == numbline)
			mouse_x -= 8;
		if (mouse_x < 0)
			mouse_x = 0;
		if (mouse_x > WCOLS)
			break;
/*
 *	Find the line on the screen
 */
		for (i = 0; i <= WECHO; i++) {
			if (vlinfo[i].vliny >= mouse_y)
				break;
		}
		if (i > WECHO)
			break;
/*
 *	Look for lines longer than one line - note  odd case at zero
 */
		if (i) {
			if (vlinfo[i - 1].vdepth > 1) {
				mouse_x += WCOLS * (mouse_y -
				    (vlinfo[i].vliny -
				    (vlinfo[i - 1].vdepth - 1)));
			}
		}
		else
		{
			mouse_x += WCOLS * (mouse_y - 1);
		}
/*
 *	Set the line
 */
		vsave();
		ocurs = cursor;
		odot = dot;
		oline = vcline;
		operate('H', i);
/*
 *	Set the column
 */
		getDOT();
		if (Pline == numbline)
			mouse_x += 8;
		vmovcol = mouse_x;
		vmoving = 1;
		wcursor = vfindcol(mouse_x);
/*
 *	Reset everything so that stuff like delete and change work
 */
		wdot = (odot - oline) + i - 1;
		cursor = ocurs;
		vcline = oline;
		dot = odot;
		getDOT();
		break;
/* #endif PTR_ADDRESSES */

	/*
	 * b		Back up a word.
	 * B		Back up a word, liberal definition.
	 */
	case 'b':
	case 'B':
		dir = -1;
		/* FALLTHROUGH */

	/*
	 * w		Forward a word.
	 * W		Forward a word, liberal definition.
	 */
	case 'W':
	case 'w':
		wdkind = c & ' ';
		forbid(lfind(2, cnt, opf, (line *)0) < 0);
		vmoving = 0;
		break;

	/*
	 * E		to end of following blank/nonblank word
	 */
	case 'E':
		wdkind = 0;
		goto ein;

	/*
	 * e		To end of following word.
	 */
	case 'e':
		wdkind = 1;
ein:
		forbid(lfind(3, cnt - 1, opf, (line *)0) < 0);
		vmoving = 0;
		break;

	/*
	 * (		Back an s-expression.
	 */
	case '(':
		dir = -1;
		/* FALLTHROUGH */

	/*
	 * )		Forward an s-expression.
	 */
	case ')':
		forbid(lfind(0, cnt, opf, (line *) 0) < 0);
		markDOT();
		break;

	/*
	 * {		Back an s-expression, but don't stop on atoms.
	 *		In text mode, a paragraph.  For C, a balanced set
	 *		of {}'s.
	 */
	case '{':
		dir = -1;
		/* FALLTHROUGH */

	/*
	 * }		Forward an s-expression, but don't stop on atoms.
	 *		In text mode, back paragraph.  For C, back a balanced
	 *		set of {}'s.
	 */
	case '}':
		forbid(lfind(1, cnt, opf, (line *) 0) < 0);
		markDOT();
		break;

	/*
	 * %		To matching () or {}.  If not at ( or { scan for
	 *		first such after cursor on this line.
	 */
	case '%':
		vsave();
		ocurs = cursor;
		odot = wdot = dot;
		oglobp = globp;
		CATCH
			i = lmatchp((line *) 0);
		ONERR
			globp = oglobp;
			dot = wdot = odot;
			cursor = ocurs;
			splitw = 0;
			vclean();
			vjumpto(dot, ocurs, 0);
			return;
		ENDCATCH
#ifdef TRACE
		if (trace)
			fprintf(trace, "after lmatchp in %, dot=%d, wdot=%d, "
			    "dol=%d\n", lineno(dot), lineno(wdot), lineno(dol));
#endif
		getDOT();
		forbid(!i);
		if (opf != vmove)
			if (dir > 0)
				wcursor++;
			else
				cursor++;
		else
			markDOT();
		vmoving = 0;
		break;

	/*
	 * [		Back to beginning of defun, i.e. an ( in column 1.
	 *		For text, back to a section macro.
	 *		For C, back to a { in column 1 (~~ beg of function.)
	 */
	case '[':
		dir = -1;
		/* FALLTHROUGH */

	/*
	 * ]		Forward to next defun, i.e. a ( in column 1.
	 *		For text, forward section.
	 *		For C, forward to a } in column 1 (if delete or such)
	 *		or if a move to a { in column 1.
	 */
	case ']':
		if (!vglobp)
			forbid(getkey() != c);
#ifndef XPG4
		forbid(Xhadcnt);
#endif
		vsave();
#ifdef XPG4
		if (cnt > 1) {
			while (cnt-- > 1) {
				i = lbrack(c, opf);
				getDOT();
				forbid(!i);
				markDOT();
				if (ospeed > B300)
					hold |= HOLDWIG;
				(*opf)(c);
			}
		}
#endif /* XPG4 */
		i = lbrack(c, opf);
		getDOT();
		forbid(!i);
		markDOT();
		if (ospeed > B300)
			hold |= HOLDWIG;
		break;

	/*
	 * ,		Invert last find with f F t or T, like inverse
	 *		of ;.
	 */
	case ',':
		forbid(lastFKND == 0);
		c = isupper(lastFKND) ? tolower(lastFKND) : toupper(lastFKND);
		i = lastFCHR;
		if (vglobp == 0)
			vglobp = (unsigned char *)"";
		subop++;
		goto nocount;

	/*
	 * 0		To beginning of real line.
	 */
	case '0':
		wcursor = linebuf;
		vmoving = 0;
		break;

	/*
	 * ;		Repeat last find with f F t or T.
	 */
	case ';':
		forbid(lastFKND == 0);
		c = lastFKND;
		i = lastFCHR;
		subop++;
		goto nocount;

	/*
	 * F		Find single character before cursor in current line.
	 * T		Like F, but stops before character.
	 */
	case 'F':	/* inverted find */
	case 'T':
		dir = -1;
		/* FALLTHROUGH */

	/*
	 * f		Find single character following cursor in current line.
	 * t		Like f, but stope before character.
	 */
	case 'f':	/* find */
	case 't':
		if (!subop) {
			int length;
			wchar_t wchar;
			length = _mbftowc(lastcp, &wchar, getesc, &Peekkey);
			if (length <= 0 || wchar == 0) {
				(void) beep();
				return;
			}
			i = wchar;
			lastcp += length;
		}
		if (vglobp == 0)
			lastFKND = c, lastFCHR = i;
		for (; cnt > 0; cnt--)
			forbid(find(i) == 0);
		vmoving = 0;
		switch (c) {

		case 'T':
			wcursor = nextchr(wcursor);
			break;

		case 't':
			wcursor = lastchr(linebuf, wcursor);
			/* FALLTHROUGH */
		case 'f':
fixup:
			if (moveop != vmove)
				wcursor = nextchr(wcursor);
			break;
		}
		break;

	/*
	 * |		Find specified print column in current line.
	 */
	case '|':
		if (Pline == numbline)
			cnt += 8;
		vmovcol = cnt;
		vmoving = 1;
		wcursor = vfindcol(cnt);
		break;

	/*
	 * ^		To beginning of non-white space on line.
	 */
	case '^':
		wcursor = vskipwh(linebuf);
		vmoving = 0;
		break;

	/*
	 * $		To end of line.
	 */
	case '$':
		if (opf == vmove) {
			vmoving = 1;
			vmovcol = 20000;
		} else
			vmoving = 0;
		if (cnt > 1) {
			if (opf == vmove) {
				wcursor = 0;
				cnt--;
			} else
				wcursor = linebuf;
			/* This is wrong at EOF */
			wdot = dot + cnt;
			break;
		}
		if (linebuf[0]) {
			wcursor = strend(linebuf);
			wcursor = lastchr(linebuf, wcursor);
			goto fixup;
		}
		wcursor = linebuf;
		break;

	/*
	 * h		Back a character.
	 * ^H		Back a character.
	 */
	case 'h':
	case CTRL('h'):
		dir = -1;
		/* FALLTHROUGH */

	/*
	 * space	Forward a character.
	 */
	case 'l':
	case ' ':
		forbid(margin() || opf == vmove && edge());
		while (cnt > 0 && !margin()) {
			if (dir == 1)
				wcursor = nextchr(wcursor);
			else
				wcursor = lastchr(linebuf, wcursor);
			cnt--;
		}
		if (margin() && opf == vmove || wcursor < linebuf) {
			if (dir == 1)
				wcursor = lastchr(linebuf, wcursor);
			else
				wcursor = linebuf;
		}
		vmoving = 0;
		break;

	/*
	 * D		Delete to end of line, short for d$.
	 */
	case 'D':
		cnt = INF;
		goto deleteit;

	/*
	 * X		Delete character before cursor.
	 */
	case 'X':
		dir = -1;
		/* FALLTHROUGH */
deleteit:
	/*
	 * x		Delete character at cursor, leaving cursor where it is.
	 */
	case 'x':
		if (margin())
			goto errlab;
		vmacchng(1);
		while (cnt > 0 && !margin()) {
			if (dir == 1)
				wcursor = nextchr(wcursor);
			else
				wcursor = lastchr(linebuf, wcursor);
			cnt--;
		}
		opf = deleteop;
		vmoving = 0;
		break;

	default:
		/*
		 * Stuttered operators are equivalent to the operator on
		 * a line, thus turn dd into d_.
		 */
		if (opf == vmove || c != workcmd[0]) {
errlab:
			(void) beep();
			vmacp = 0;
			return;
		}
		/* FALLTHROUGH */

	/*
	 * _		Target for a line or group of lines.
	 *		Stuttering is more convenient; this is mostly
	 *		for aesthetics.
	 */
	case '_':
		wdot = dot + cnt - 1;
		vmoving = 0;
		wcursor = 0;
		break;

	/*
	 * H		To first, home line on screen.
	 *		Count is for count'th line rather than first.
	 */
	case 'H':
		wdot = (dot - vcline) + cnt - 1;
		if (opf == vmove)
			markit(wdot);
		vmoving = 0;
		wcursor = 0;
		break;

	/*
	 * -		Backwards lines, to first non-white character.
	 */
	case '-':
		wdot = dot - cnt;
		vmoving = 0;
		wcursor = 0;
		break;

	/*
	 * ^P		To previous line same column.  Ridiculous on the
	 *		console of the VAX since it puts console in LSI mode.
	 */
	case 'k':
	case CTRL('p'):
		wdot = dot - cnt;
		if (vmoving == 0)
			vmoving = 1, vmovcol = column(cursor);
		wcursor = 0;
		break;

	/*
	 * L		To last line on screen, or count'th line from the
	 *		bottom.
	 */
	case 'L':
		wdot = dot + vcnt - vcline - cnt;
		if (opf == vmove)
			markit(wdot);
		vmoving = 0;
		wcursor = 0;
		break;

	/*
	 * M		To the middle of the screen.
	 */
	case 'M':
		wdot = dot + ((vcnt + 1) / 2) - vcline - 1;
		if (opf == vmove)
			markit(wdot);
		vmoving = 0;
		wcursor = 0;
		break;

	/*
	 * +		Forward line, to first non-white.
	 *
	 * CR		Convenient synonym for +.
	 */
	case '+':
	case CR:
		wdot = dot + cnt;
		vmoving = 0;
		wcursor = 0;
		break;

	/*
	 * ^N		To next line, same column if possible.
	 *
	 * LF		Linefeed is a convenient synonym for ^N.
	 */
	case CTRL('n'):
	case 'j':
	case NL:
		wdot = dot + cnt;
		if (vmoving == 0)
			vmoving = 1, vmovcol = column(cursor);
		wcursor = 0;
		break;

	/*
	 * n		Search to next match of current pattern.
	 */
	case 'n':
		vglobp = vscandir;
		c = *vglobp++;
		goto nocount;

	/*
	 * N		Like n but in reverse direction.
	 */
	case 'N':
		vglobp = vscandir[0] == '/' ? (unsigned char *)"?" :
		    (unsigned char *)"/";
		c = *vglobp++;
		goto nocount;

	/*
	 * '		Return to line specified by following mark,
	 *		first white position on line.
	 *
	 * `		Return to marked line at remembered column.
	 */
	case '\'':
	case '`':
		d = c;
		c = getesc();
		if (c == 0)
			return;
		c = markreg(c);
		forbid(c == 0);
		wdot = getmark(c);
		forbid(wdot == NOLINE);
		forbid(Xhadcnt);
		vmoving = 0;
		wcursor = d == '`' ? ncols[c - 'a'] : 0;
		if (opf == vmove && (wdot != dot ||
		    (d == '`' && wcursor != cursor)))
			markDOT();
		if (wcursor) {
			vsave();
			getaline(*wdot);
			if (wcursor > strend(linebuf))
				wcursor = 0;
			else {
				cnt = wcursor - linebuf;
				/*CSTYLED*/
				for (wcursor = linebuf; wcursor - linebuf < cnt; ) 
					wcursor = nextchr(wcursor);
				if (wcursor - linebuf > cnt)
					wcursor = lastchr(linebuf, wcursor);
			}
			getDOT();
		}
		if (ospeed > B300)
			hold |= HOLDWIG;
		break;

	/*
	 * G		Goto count'th line, or last line if no count
	 *		given.
	 */
	case 'G':
		if (!Xhadcnt)
			cnt = lineDOL();
		wdot = zero + cnt;
		forbid(wdot < one || wdot > dol);
		if (opf == vmove)
			markit(wdot);
		vmoving = 0;
		wcursor = 0;
		break;

	/*
	 * /		Scan forward for following re.
	 * ?		Scan backward for following re.
	 */
	case '/':
	case '?':
		forbid(Xhadcnt);
		vsave();
		oc = c;
		ocurs = cursor;
		odot = dot;
		wcursor = 0;
		if (readecho(c))
			return;
		if (!vglobp)
			vscandir[0] = genbuf[0];
		oglobp = globp; CP(vutmp, genbuf); globp = vutmp;
		d = peekc;
fromsemi:
		ungetchar(0);
		fixech();
		CATCH
#ifndef CBREAK
			/*
			 * Lose typeahead (ick).
			 */
			vcook();
#endif
			addr = address(cursor);
#ifndef CBREAK
			vraw();
#endif
		ONERR
#ifndef CBREAK
			vraw();
#endif
slerr:
			globp = oglobp;
			dot = odot;
			cursor = ocurs;
			ungetchar(d);
			splitw = 0;
			vclean();
			vjumpto(dot, ocurs, 0);
			return;
		ENDCATCH
		if (globp == 0)
			globp = (unsigned char *)"";
		else if (peekc)
			--globp;
		if (*globp == ';') {
			/* /foo/;/bar/ */
			globp++;
			dot = addr;
			cursor = (unsigned char *)loc1;
			goto fromsemi;
		}
		dot = odot;
		ungetchar(d);
		c = 0;
		if (*globp == 'z')
			globp++, c = '\n';
		if (any(*globp, "^+-."))
			c = *globp++;
		i = 0;
		while (isdigit(*globp))
			i = i * 10 + *globp++ - '0';
		if (any(*globp, "^+-."))
			c = *globp++;
		if (*globp) {
			/* random junk after the pattern */
			(void) beep();
			goto slerr;
		}
		globp = oglobp;
		splitw = 0;
		vmoving = 0;
		wcursor = (unsigned char *)loc1;
		if (i != 0)
			vsetsiz(i);
		if (opf == vmove) {
			if (state == ONEOPEN || state == HARDOPEN)
				outline = destline = WBOT;
			if (addr != dot || (unsigned char *)loc1 != cursor)
				markDOT();
			if (loc1 > (char *)linebuf && *loc1 == 0)
				loc1 = (char *)lastchr(linebuf, loc1);
			if (c)
				vjumpto(addr, (unsigned char *)loc1, c);
			else {
				vmoving = 0;
				if (loc1) {
					vmoving++;
					vmovcol = column(loc1);
				}
				getDOT();
				if (state == CRTOPEN && addr != dot)
					vup1();
				vupdown(addr - dot, NOSTR);
			}
			if (oc == '/') {	/* forward search */
				if (dot < odot ||
				    (dot == odot && cursor <= ocurs))
					warnf(value(vi_TERSE) ?
			gettext("Search wrapped BOTTOM") :
			gettext("Search wrapped around BOTTOM of buffer"));
			} else {		/* backward search */
				if (dot > odot ||
				    (dot == odot && cursor >= ocurs))
					warnf(value(vi_TERSE) ?
			gettext("Search wrapped TOP") :
			gettext("Search wrapped around TOP of buffer"));
			}
			return;
		}
		lastcp[-1] = 'n';
		getDOT();
		wdot = addr;
		break;
	}
	/*
	 * Apply.
	 */
	if (vreg && wdot == 0)
		wdot = dot;
	(*opf)(c);
	wdot = NOLINE;
}

static void
lfixol()
{
	unsigned char *savevglobp;
	int savesplit;

	if (Outchar == vputchar)
		return;

	/* Show messages */
	putnl();
	if (inopen > 0 && clr_eol)
		vclreol();
	if (enter_standout_mode && exit_bold)
		putpad((unsigned char *)enter_standout_mode);
	lprintf(gettext("[Hit return to continue] "), 0);
	if (enter_standout_mode && exit_bold)
		putpad((unsigned char *)exit_bold);

	/* Get key input for confirmation */
	savevglobp = vglobp;
	vglobp = 0; /* force typed input */
	getkey();
	vglobp = savevglobp;

	/* reset output function */
	Outchar = vputchar;

	/* Clean up screen */
	savesplit = splitw;
	splitw = 0;
	vclear();
	vdirty(0, WLINES);
	vredraw(WTOP);
	splitw = savesplit;
}

void
warnf(char *str, char *cp)
{
	int saveline, savecol, savesplit;

	saveline = outline;
	savecol = outcol;
	savesplit = splitw;
	splitw = 1;
	vgoto(WECHO, 0);
	if (!enter_standout_mode || !exit_bold)
		dingdong();
	if (clr_eol)
		vclreol();
	if (enter_standout_mode && exit_bold)
		putpad((unsigned char *)enter_standout_mode);
	lprintf(str, cp);
	if (enter_standout_mode && exit_bold)
		putpad((unsigned char *)exit_bold);
	lfixol();
	vgoto(saveline, savecol);
	splitw = savesplit;
}

/* #ifdef PTR_ADDRESSES */
/*
 *	read in a row or column address
 *
 */
static int
get_addr()
{
	short  c;
	short  next;

	c = getkey();
	next = 0;
	switch (c) {
	case CTRL('A'):
		next = 96;
		c = getkey();
		break;

	case CTRL('B'):
		next = 192;
		c = getkey();
		break;
	}
	if (c < ' ')
		return (-1);
	return (next + c - ' ');
}
/* #endif PTR_ADDRESSES */

/*
 * Find single character c, in direction dir from cursor.
 */
int
find(wchar_t c)
{

	wchar_t wchar;
	int length;
	for (;;) {
		if (edge())
			return (0);
		if (dir == 1)
			wcursor = nextchr(wcursor);
		else
			wcursor = lastchr(linebuf, wcursor);
		if ((length = mbtowc(&wchar, (char *)wcursor,
		    MULTI_BYTE_MAX)) > 0 && wchar == c)
			return (1);
	}
}

/*
 * Do a word motion with operator op, and cnt more words
 * to go after this.
 */
int
word(int (*op)(), int cnt)
{
	int which;
	unsigned char *iwc;
	line *iwdot = wdot;
	wchar_t wchar;
	int length;

	if (dir == 1) {
		iwc = wcursor;
		which = wordch(wcursor);
		while (wordof(which, wcursor)) {
			length = mbtowc(&wchar, (char *)wcursor,
			    MULTI_BYTE_MAX);
			if (length <= 0)
				length = 1;
			if (cnt == 1 && op != vmove && wcursor[length] == 0) {
				wcursor += length;
				break;
			}
			if (!lnext())
				return (0);
			if (wcursor == linebuf)
				break;
		}
		/* Unless last segment of a change skip blanks */
		if (op != (int (*)())vchange || cnt > 1)
			while (!margin() && blank()) {
				if (!lnext())
					return (0);
			}
		else
			if (wcursor == iwc && iwdot == wdot && *iwc)
				wcursor = nextchr(wcursor);
		if (op == vmove && margin()) {
			wcursor = lastchr(linebuf, wcursor);
#ifdef XPG4
			if (wcursor < linebuf) {
				wcursor = linebuf;
			}
#endif /* XPG4 */
		}
	} else {
		if (!lnext())
			return (0);
		while (blank())
			if (!lnext())
				return (0);
		if (!margin()) {
			which = wordch(wcursor);
			while (!margin() && wordof(which, wcursor))
				wcursor = lastchr(linebuf, wcursor);
		}
#ifdef PRESUNEUC
		if (wcursor < linebuf || !wordof(which, wcursor))
			wcursor = nextchr(wcursor);
#else
		if (wcursor < linebuf)
			wcursor++;
		else if (!wordof(which, wcursor))
			wcursor = nextchr(wcursor);
#endif /* PRESUNEUC */
	}
	return (1);
}

/*
 * To end of word, with operator op and cnt more motions
 * remaining after this.
 */
int
eend(int (*op)())
{
	int which;

	if (!lnext())
		return (0);
	while (blank())
		if (!lnext())
			return (0);
	which = wordch(wcursor);
	while (wordof(which, wcursor)) {
		if (wcursor[1] == 0) {
			wcursor = nextchr(wcursor);
			break;
		}
		if (!lnext())
			return (0);
	}
	if (op == vyankit)
		wcursor = lastchr(linebuf, wcursor) + 1;
	else if (op != (int (*)())vchange && op != (int (*)())vdelete &&
	    wcursor > linebuf)
		wcursor = lastchr(linebuf, wcursor);
	return (1);
}

/*
 * Wordof tells whether the character at *wc is in a word of
 * kind which (blank/nonblank words are 0, conservative words 1).
 */
int
wordof(unsigned char which, unsigned char *wc)
{
#ifdef PRESUNEUC

	if (isspace(*wc))
#else
	wchar_t z;

	(void) mbtowc(&z, (char *)wc, MB_LEN_MAX);
	if (iswspace(z))
#endif /* PRESUNEUC */
		return (0);
	return (!wdkind || wordch(wc) == which);
}

/*
 * Wordch tells whether character at *wc is a word character
 * i.e. an alfa, digit, or underscore.
 */
#ifdef PRESUNEUC
#define	SS2 0216
#define	SS3 0217
#endif /* PRESUNEUC */

int
wordch(unsigned char *wc)
{
	int length;
	wchar_t c;

	length = mbtowc(&c, (char *)wc, MULTI_BYTE_MAX);
	if (length <= 0)
		return (0);
	if (length > 1)
#ifndef PRESUNEUC
		if (wdwc)
			return (*wdwc)(c);
		else
#endif /* PRESUNEUC */
		return (length);
#ifndef PRESUNEUC
	return (isalpha(*wc) || isdigit(*wc) || *wc == '_');
#else
	return (isalpha(c) || isdigit(c) || c == '_');
#endif /* PRESUNEUC */
}

/*
 * Edge tells when we hit the last character in the current line.
 */
int
edge(void)
{

	if (linebuf[0] == 0)
		return (1);
	if (dir == 1)
		return (*(nextchr(wcursor)) == 0);
	else
		return (wcursor == linebuf);
}

/*
 * Margin tells us when we have fallen off the end of the line.
 */
int
margin(void)
{

	return (wcursor < linebuf || wcursor[0] == 0);
}
#ifndef PRESUNEUC

/*
 * Blank tells if the cursor is currently on a TAB, RETURN,
 * NEWLINE, FORMFEED, bertical tab, or SPACE character from EUC
 * primary and supplementary codesets.
 */
int
blank(void)
{
	wchar_t z;

	(void) mbtowc(&z, (char *)wcursor, MB_CUR_MAX);
	return (iswspace((int)z));
}
#endif /* PRESUNEUC */
