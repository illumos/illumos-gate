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


/* Copyright (c) 1981 Regents of the University of California */
#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "ex.h"
#include "ex_tty.h"
#include "ex_vis.h"
#ifndef PRESUNEUC
#include <wctype.h>
/* Undef putchar/getchar if they're defined. */
#ifdef putchar
#	undef putchar
#endif
#ifdef getchar
#	undef getchar
#endif
#endif /* PRESUNEUC */

/*
 * Terminal driving and line formatting routines.
 * Basic motion optimizations are done here as well
 * as formatting of lines (printing of control characters,
 * line numbering and the like).
 */

/*
 * The routines outchar, putchar and pline are actually
 * variables, and these variables point at the current definitions
 * of the routines.  See the routine setflav.
 * We sometimes make outchar be routines which catch the characters
 * to be printed, e.g. if we want to see how long a line is.
 * During open/visual, outchar and putchar will be set to
 * routines in the file ex_vput.c (vputchar, vinschar, etc.).
 */
int	(*Outchar)() = termchar;
int	(*Putchar)() = normchar;
int	(*Pline)() = normline;
static unsigned char multic[MULTI_BYTE_MAX];
bool putoctal; /* flag to say if byte should be printed as octal */
int termiosflag = -1; /* flag for using termios ioctl
			      * structure */

int (*
setlist(t))()
	bool t;
{
	int (*P)();

	listf = t;
	P = Putchar;
	Putchar = t ? listchar : normchar;
	return (P);
}

int (*
setnumb(t))()
	bool t;
{
	int (*P)();

	numberf = t;
	P = Pline;
	Pline = t ? (int (*)())numbline : normline;
	return (P);
}

/*
 * Format c for list mode; leave things in common
 * with normal print mode to be done by normchar.
 */
int
listchar(wchar_t c)
{

	c &= (int)(TRIM|QUOTE);
	switch (c) {

	case '\t':
	case '\b':
		outchar('^');
		c = ctlof(c);
		break;

	case '\n':
		break;

	case (int)('\n' | QUOTE):
		outchar('$');
		break;

	default:
		if((int)(c & QUOTE))
			break;
		if (c < ' ' && c != '\n' || c == DELETE)
			outchar('^'), c = ctlof(c);
	}
	(void) normchar(c);
	return (0);
}

/*
 * Format c for printing.  Handle funnies of upper case terminals
 * and hazeltines which don't have ~.
 */
int
normchar(wchar_t c)
{
	char *colp;

	c &= (int)(TRIM|QUOTE);
	if (c == '~' && tilde_glitch) {
		(void) normchar('\\');
		c = '^';
	}
	if ((int)(c & QUOTE))
		switch (c) {

		case (int)(' ' | QUOTE):
		case (int)('\b' | QUOTE):
			break;

		case (int)QUOTE:
			return (0);

		default:
			c &= (int)TRIM;
		}
	else if (c < ' ' && (c != '\b' || !over_strike) && c != '\n' && c != '\t' || c == DELETE)
		putchar('^'), c = ctlof(c);
	else if (c >= 0200 && (putoctal || !iswprint(c))) {
		outchar('\\');
		outchar(((c >> 6) & 07) + '0');
		outchar(((c >> 3) & 07) + '0');
		outchar((c & 07) + '0');
		return (0);
	} else if (UPPERCASE)
		if (isupper(c)) {
			outchar('\\');
			c = tolower(c);
		} else {
			colp = "({)}!|^~'`";
			while (*colp++)
				if (c == *colp++) {
					outchar('\\');
					c = colp[-2];
					break;
				}
		}
	outchar(c);
	return (0);
}

/*
 * Print a line with a number.
 */
int
numbline(int i)
{

	if (shudclob)
		slobber(' ');
	viprintf("%6d  ", i);
	(void) normline();
	return (0);
}

/*
 * Normal line output, no numbering.
 */
int
normline(void)
{
	unsigned char *cp;
	int n;
	wchar_t wchar;
	if (shudclob)
		slobber(linebuf[0]);
	/* pdp-11 doprnt is not reentrant so can't use "printf" here
	   in case we are tracing */
	for (cp = linebuf; *cp;) 
		if((n = mbtowc(&wchar, (char *)cp, MULTI_BYTE_MAX)) < 0) {
			putoctal = 1;
			putchar(*cp++);
			putoctal = 0;
		} else {
			cp += n;
			putchar(wchar);
		}
	if (!inopen)
		putchar((int)('\n' | QUOTE));
	return (0);
}

/*
 * Given c at the beginning of a line, determine whether
 * the printing of the line will erase or otherwise obliterate
 * the prompt which was printed before.  If it won't, do it now.
 */
void
slobber(int c)
{

	shudclob = 0;
	switch (c) {

	case '\t':
		if (Putchar == listchar)
			return;
		break;

	default:
		return;

	case ' ':
	case 0:
		break;
	}
	if (over_strike)
		return;
	flush();
	(void) putch(' ');
	tputs(cursor_left, 0, putch);
}

/*
 * The output buffer is initialized with a useful error
 * message so we don't have to keep it in data space.
 */
static	wchar_t linb[66];
wchar_t *linp = linb;

/*
 * Phadnl records when we have already had a complete line ending with \n.
 * If another line starts without a flush, and the terminal suggests it,
 * we switch into -nl mode so that we can send linefeeds to avoid
 * a lot of spacing.
 */
static	bool phadnl;

/*
 * Indirect to current definition of putchar.
 */
int
putchar(int c)
{
	return ((*Putchar)((wchar_t)c));
}

/*
 * Termchar routine for command mode.
 * Watch for possible switching to -nl mode.
 * Otherwise flush into next level of buffering when
 * small buffer fills or at a newline.
 */
int
termchar(wchar_t c)
{

	if (pfast == 0 && phadnl)
		pstart();
	if (c == '\n')
		phadnl = 1;
	else if (linp >= &linb[63])
		flush1();
	*linp++ = c;
	if (linp >= &linb[63]) {
		fgoto();
		flush1();
	}
	return (0);
}

void
flush(void)
{

	flush1();
	flush2();
}

/*
 * Flush from small line buffer into output buffer.
 * Work here is destroying motion into positions, and then
 * letting fgoto do the optimized motion.
 */
void
flush1(void)
{
	wchar_t *lp;
	wchar_t c;
#ifdef PRESUNEUC
	/* used for multibyte characters split between lines */
	int splitcnt = 0;
#else
	/* used for multicolumn character substitution and padding */
	int fillercnt = 0;
#endif /* PRESUNEUC */
	*linp = 0;
	lp = linb;
	while (*lp)
		switch (c = *lp++) {

		case '\r':
			destline += destcol / columns;
			destcol = 0;
			continue;

		case '\b':
			if (destcol)
				destcol--;
			continue;

		case ' ':
			destcol++;
			continue;

		case '\t':
			destcol += value(vi_TABSTOP) - destcol % value(vi_TABSTOP);
			continue;

		case '\n':
			destline += destcol / columns + 1;
			if (destcol != 0 && destcol % columns == 0)
				destline--;
			destcol = 0;
			continue;

		default:
			fgoto();
			for (;;) {
				int length, length2;
				unsigned char *p;
				c &= TRIM;
				if ((length = wcwidth(c)) < 0)
					length = 0;
				if (auto_right_margin == 0 && outcol >= columns)
					fgoto();
				if((destcol % columns) + length - 1 >= columns) {
#ifdef PRESUNEUC
					/* represent split chars by '>' */
					splitcnt = length - 1;
					c = '>';
#else
					/* substitute/wrap multicolumn char */
					if(mc_wrap) {
						fillercnt = columns -
							    (destcol % columns);
						while(fillercnt) {
							(void) putch(mc_filler);
							outcol++;
							destcol++;
							fillercnt--;
						}
					} else {
						fillercnt = length - 1;
						c = mc_filler;
					}
#endif /* PRESUNEUC */
					continue;
				}
				length2 = wctomb((char *)multic, c);
				p = multic;
				while(length2--)
					(void) putch(*p++);
				if (c == '\b') {
					outcol--;
					destcol--;
				} else if (c >= ' ' && c != DELETE) {
					outcol += length;
					destcol += length;
					if (eat_newline_glitch && outcol % columns == 0)
						(void) putch('\r'),
						    (void) putch('\n');
				}
#ifdef PRESUNEUC
				if(splitcnt) {
					splitcnt--;
					c = '>';
				} else
					c = *lp++;
#else
				if(fillercnt) {
					fillercnt--;
					c = mc_filler;
					if(c == ' ')
						continue;
				} else
					c = *lp++;
#endif /* PRESUNEUC */
				if (c <= ' ')
					break;
			}
			--lp;
			continue;
		}
	linp = linb;
}

void
flush2(void)
{

	fgoto();
	flusho();
	pstop();
}

/*
 * Sync the position of the output cursor.
 * Most work here is rounding for terminal boundaries getting the
 * column position implied by wraparound or the lack thereof and
 * rolling up the screen to get destline on the screen.
 */
void
fgoto(void)
{
	int l, c;

	if (destcol > columns - 1) {
		destline += destcol / columns;
		destcol %= columns;
	}
	if (outcol > columns - 1) {
		l = (outcol + 1) / columns;
		outline += l;
		outcol %= columns;
		if (auto_right_margin == 0) {
			while (l > 0) {
				if (pfast)
					tputs(carriage_return, 0, putch);
				tputs(cursor_down, 0, putch);
				l--;
			}
			outcol = 0;
		}
		if (outline > lines - 1) {
			destline -= outline - (lines - 1);
			outline = lines - 1;
		}
	}
	if (destline > lines - 1) {
		l = destline;
		destline = lines - 1;
		if (outline < lines - 1) {
			c = destcol;
			if (pfast == 0 && (!cursor_address || holdcm))
				destcol = 0;
			fgoto();
			destcol = c;
		}
		while (l > lines - 1) {
			/*
			 * The following linefeed (or simulation thereof)
			 * is supposed to scroll up the screen, since we
			 * are on the bottom line.
			 *
			 * Superbee glitch:  in the middle of the screen we
			 * have to use esc B (down) because linefeed messes up
			 * in "Efficient Paging" mode (which is essential in
			 * some SB's because CRLF mode puts garbage
			 * in at end of memory), but you must use linefeed to
			 * scroll since down arrow won't go past memory end.
			 * I turned this off after receiving Paul Eggert's
			 * Superbee description which wins better.
			 */
			if (scroll_forward /* && !beehive_glitch */ && pfast)
				tputs(scroll_forward, 0, putch);
			else
				(void) putch('\n');
			l--;
			if (pfast == 0)
				outcol = 0;
		}
	}
	if (destline < outline && !(cursor_address && !holdcm || cursor_up || cursor_home))
		destline = outline;
	if (cursor_address && !holdcm)
		if (plod(costCM) > 0) 
			plod(0);
		else
			tputs(tparm(cursor_address, destline, destcol), 0, putch);
	else
		plod(0);
	outline = destline;
	outcol = destcol;
}

/*
 * Tab to column col by flushing and then setting destcol.
 * Used by "set all".
 */
void
gotab(int col)
{

	flush1();
	destcol = col;
}

/*
 * Move (slowly) to destination.
 * Hard thing here is using home cursor on really deficient terminals.
 * Otherwise just use cursor motions, hacking use of tabs and overtabbing
 * and backspace.
 */

static int plodcnt, plodflg;

int
#ifdef __STDC__
plodput(char c)
#else
plodput(c)
char c;
#endif
{

	if (plodflg)
		plodcnt--;
	else
		(void) putch(c);
	return (0);
}

int
plod(int cnt)
{
	int i, j, k;
	int soutcol, soutline;

	plodcnt = plodflg = cnt;
	soutcol = outcol;
	soutline = outline;
	/*
	 * Consider homing and moving down/right from there, vs moving
	 * directly with local motions to the right spot.
	 */
	if (cursor_home) {
		/*
		 * i is the cost to home and tab/space to the right to
		 * get to the proper column.  This assumes cursor_right costs
		 * 1 char.  So i+destcol is cost of motion with home.
		 */
		if (tab && value(vi_HARDTABS))
			i = (destcol / value(vi_HARDTABS)) + (destcol % value(vi_HARDTABS));
		else
			i = destcol;
		/*
		 * j is cost to move locally without homing
		 */
		if (destcol >= outcol) {	/* if motion is to the right */
			if (value(vi_HARDTABS)) {
				j = destcol / value(vi_HARDTABS) - outcol / value(vi_HARDTABS);
				if (tab && j)
					j += destcol % value(vi_HARDTABS);
				else
					j = destcol - outcol;
			} else
				j = destcol - outcol;
		} else
			/* leftward motion only works if we can backspace. */
			if (outcol - destcol <= i && (cursor_left))
				i = j = outcol - destcol; /* cheaper to backspace */
			else
				j = i + 1; /* impossibly expensive */

		/* k is the absolute value of vertical distance */
		k = outline - destline;
		if (k < 0)
			k = -k;
		j += k;

		/*
		 * Decision.  We may not have a choice if no cursor_up.
		 */
		if (i + destline < j || (!cursor_up && destline < outline)) {
			/*
			 * Cheaper to home.  Do it now and pretend it's a
			 * regular local motion.
			 */
			tputs(cursor_home, 0, plodput);
			outcol = outline = 0;
		} else if (cursor_to_ll) {
			/*
			 * Quickly consider homing down and moving from there.
			 * Assume cost of cursor_to_ll is 2.
			 */
			k = (lines - 1) - destline;
			if (i + k + 2 < j && (k<=0 || cursor_up)) {
				tputs(cursor_to_ll, 0, plodput);
				outcol = 0;
				outline = lines - 1;
			}
		}
	} else
		/*
		 * No home and no up means it's impossible, so we return an
		 * incredibly big number to make cursor motion win out.
		 */
		if (!cursor_up && destline < outline)
			return (500);
	if (tab && value(vi_HARDTABS))
		i = destcol % value(vi_HARDTABS)
		    + destcol / value(vi_HARDTABS);
	else
		i = destcol;
/*
	if (back_tab && outcol > destcol && (j = (((outcol+7) & ~7) - destcol - 1) >> 3)) {
		j *= (k = strlen(back_tab));
		if ((k += (destcol&7)) > 4)
			j += 8 - (destcol&7);
		else
			j += k;
	} else
*/
		j = outcol - destcol;
	/*
	 * If we will later need a \n which will turn into a \r\n by
	 * the system or the terminal, then don't bother to try to \r.
	 */
	if ((NONL || !pfast) && outline < destline)
		goto dontcr;
	/*
	 * If the terminal will do a \r\n and there isn't room for it,
	 * then we can't afford a \r.
	 */
	if (!carriage_return && outline >= destline)
		goto dontcr;
	/*
	 * If it will be cheaper, or if we can't back up, then send
	 * a return preliminarily.
	 */
	if (j > i + 1 || outcol > destcol && !cursor_left) {
		/*
		 * BUG: this doesn't take the (possibly long) length
		 * of carriage_return into account.
		 */
		if (carriage_return) {
			tputs(carriage_return, 0, plodput);
			outcol = 0;
		} else if (newline) {
			tputs(newline, 0, plodput);
			outline++;
			outcol = 0;
		}
	}
dontcr:
	/* Move down, if necessary, until we are at the desired line */
	while (outline < destline) {
		j = destline - outline;
		if (j > costDP && parm_down_cursor) {
			/* Win big on Tek 4025 */
			tputs(tparm(parm_down_cursor, j), j, plodput);
			outline += j;
		}
		else {
			outline++;
			if (cursor_down && pfast)
				tputs(cursor_down, 0, plodput);
			else
				(void) plodput('\n');
		}
		if (plodcnt < 0)
			goto out;
		if (NONL || pfast == 0)
			outcol = 0;
	}
	if (back_tab)
		k = strlen(back_tab);	/* should probably be cost(back_tab) and moved out */
	/* Move left, if necessary, to desired column */
	while (outcol > destcol) {
		if (plodcnt < 0)
			goto out;
		if (back_tab && !insmode && outcol - destcol > 4+k) {
			tputs(back_tab, 0, plodput);
			outcol--;
			if (value(vi_HARDTABS))
				outcol -= outcol % value(vi_HARDTABS); /* outcol &= ~7; */
			continue;
		}
		j = outcol - destcol;
		if (j > costLP && parm_left_cursor) {
			tputs(tparm(parm_left_cursor, j), j, plodput);
			outcol -= j;
		}
		else {
			outcol--;
			tputs(cursor_left, 0, plodput);
		}
	}
	/* Move up, if necessary, to desired row */
	while (outline > destline) {
		j = outline - destline;
		if (parm_up_cursor && j > 1) {
			/* Win big on Tek 4025 */
			tputs(tparm(parm_up_cursor, j), j, plodput);
			outline -= j;
		}
		else {
			outline--;
			tputs(cursor_up, 0, plodput);
		}
		if (plodcnt < 0)
			goto out;
	}
	/*
	 * Now move to the right, if necessary.  We first tab to
	 * as close as we can get.
	 */
	if (value(vi_HARDTABS) && tab && !insmode && destcol - outcol > 1) {
		/* tab to right as far as possible without passing col */
		for (;;) {
			i = tabcol(outcol, value(vi_HARDTABS));
			if (i > destcol)
				break;
			if (tab)
				tputs(tab, 0, plodput);
			else
				(void) plodput('\t');
			outcol = i;
		}
		/* consider another tab and then some backspaces */
		if (destcol - outcol > 4 && i < columns && cursor_left) {
			tputs(tab, 0, plodput);
			outcol = i;
			/*
			 * Back up.  Don't worry about parm_left_cursor because
			 * it's never more than 4 spaces anyway.
			 */
			while (outcol > destcol) {
				outcol--;
				tputs(cursor_left, 0, plodput);
			}
		}
	}
	/*
	 * We've tabbed as much as possible.  If we still need to go
	 * further (not exact or can't tab) space over.  This is a
	 * very common case when moving to the right with space.
	 */
	while (outcol < destcol) {
		j = destcol - outcol;
		if (j > costRP && parm_right_cursor) {
			/*
			 * This probably happens rarely, if at all.
			 * It seems mainly useful for ANSI terminals
			 * with no hardware tabs, and I don't know
			 * of any such terminal at the moment.
			 */
			tputs(tparm(parm_right_cursor, j), j, plodput);
			outcol += j;
		}
		else {
			/*
			 * move one char to the right.  We don't use right
			 * because it's better to just print the char we are
			 * moving over.  There are various exceptions, however.
			 * If !inopen, vtube contains garbage.  If the char is
			 * a null or a tab we want to print a space.  Other
			 * random chars we use space for instead, too.
			 */
			wchar_t wchar;
			int length, scrlength;
			unsigned char multic[MB_LEN_MAX];

			if (!inopen || vtube[outline]==NULL ||
				(wchar=vtube[outline][outcol]) < ' ')
				wchar = ' ';
			if((int)(wchar & QUOTE))	/* no sign extension on 3B */
				wchar = ' ';
			length = wctomb((char *)multic, wchar);
			if ((scrlength = wcwidth(wchar)) < 0)
				scrlength = 0;
			/* assume multibyte terminals have cursor_right */
			if (insmode && cursor_right || length > 1 || wchar == FILLER) {
				int diff = destcol - outcol;
				j = (wchar == FILLER ? 1 : scrlength > diff ? diff : scrlength);
				while(j--) {
					outcol++;
					tputs(cursor_right, 0, plodput);
				}
			} else {
				(void) plodput((char)multic[0]);
				outcol++;
			}
		}
		if (plodcnt < 0)
			goto out;
	}
out:
	if(plodflg) {
		outcol = soutcol;
		outline = soutline;
	}
	return(plodcnt);
}

/*
 * An input line arrived.
 * Calculate new (approximate) screen line position.
 * Approximate because kill character echoes newline with
 * no feedback and also because of long input lines.
 */
void
noteinp(void)
{

	outline++;
	if (outline > lines - 1)
		outline = lines - 1;
	destline = outline;
	destcol = outcol = 0;
}

/*
 * Something weird just happened and we
 * lost track of what's happening out there.
 * Since we can't, in general, read where we are
 * we just reset to some known state.
 * On cursor addressable terminals setting to unknown
 * will force a cursor address soon.
 */
void
termreset(void)
{

	endim();
	if (enter_ca_mode)
		putpad((unsigned char *)enter_ca_mode);
	destcol = 0;
	destline = lines - 1;
	if (cursor_address) {
		outcol = UKCOL;
		outline = UKCOL;
	} else {
		outcol = destcol;
		outline = destline;
	}
}

/*
 * Low level buffering, with the ability to drain
 * buffered output without printing it.
 */
unsigned char	*obp = obuf;

void
draino(void)
{

	obp = obuf;
}

void
flusho(void)
{
	if (obp != obuf) {
		write(1, obuf, obp - obuf);
#ifdef TRACE
		if (trace)
			fwrite(obuf, 1, obp-obuf, trace);
#endif
		obp = obuf;
	}
}

void
putnl(void)
{

	putchar('\n');
}

void
putS(unsigned char *cp)
{

	if (cp == NULL)
		return;
	while (*cp)
		(void) putch(*cp++);
}

int
putch(char c)
{

#ifdef OLD3BTTY		
	if(c == '\n')	/* Fake "\n\r" for '\n' til fix in 3B firmware */
		(void) putch('\r'); /* vi does "stty -icanon" => -onlcr !! */
#endif
	*obp++ = c;
	if (obp >= &obuf[sizeof obuf])
		flusho();
	return (0);
}

/*
 * Miscellaneous routines related to output.
 */

/*
 * Put with padding
 */
void
putpad(unsigned char *cp)
{

	flush();
	tputs((char *)cp, 0, putch);
}

/*
 * Set output through normal command mode routine.
 */
void
setoutt(void)
{

	Outchar = termchar;
}

/*
 * Printf (temporarily) in list mode.
 */
/*VARARGS2*/
void
lprintf(unsigned char *cp, unsigned char *dp, ...)
{
	int (*P)();

	P = setlist(1);
#ifdef PRESUNEUC
	viprintf(cp, dp);
#else
	viprintf((char *)cp, (char *)dp);
#endif /* PRESUNEUC */
	Putchar = P;
}

/*
 * Newline + flush.
 */
void
putNFL()
{

	putnl();
	flush();
}

/*
 * Try to start -nl mode.
 */
void
pstart(void)
{

	if (NONL)
		return;
 	if (!value(vi_OPTIMIZE))
		return;
	if (ruptible == 0 || pfast)
		return;
	fgoto();
	flusho();
	pfast = 1;
	normtty++;
	tty = normf;
	tty.c_oflag &= ~(ONLCR|TAB3);
	tty.c_lflag &= ~ECHO;
	saveterm();
	sTTY(2);
}

/*
 * Stop -nl mode.
 */
void
pstop(void)
{

	if (inopen)
		return;
	phadnl = 0;
	linp = linb;
	draino();
	normal(normf);
	pfast &= ~1;
}

/*
 * Prep tty for open mode.
 */
ttymode
ostart()
{
	ttymode f;

	/*
	if (!intty)
		error("Open and visual must be used interactively");
	*/
	(void) gTTY(2);
	normtty++;
	f = tty;
	tty = normf;
	tty.c_iflag &= ~ICRNL;
	tty.c_lflag &= ~(ECHO|ICANON);
	tty.c_oflag &= ~(TAB3|ONLCR);
	tty.c_cc[VMIN] = 1;
	tty.c_cc[VTIME] = 1;
	ttcharoff();
	sTTY(2);
	tostart();
	pfast |= 2;
	saveterm();
	return (f);
}

/* actions associated with putting the terminal in open mode */
void
tostart(void)
{
	putpad((unsigned char *)cursor_visible);
	putpad((unsigned char *)keypad_xmit);
	if (!value(vi_MESG)) {
		if (ttynbuf[0] == 0) {
			char *tn;
			if ((tn=ttyname(2)) == NULL &&
			    (tn=ttyname(1)) == NULL &&
			    (tn=ttyname(0)) == NULL)
				ttynbuf[0] = 1;
			else
				strcpy(ttynbuf, tn);
		}
		if (ttynbuf[0] != 1) {
			struct stat64 sbuf;
			stat64((char *)ttynbuf, &sbuf);
			ttymesg = FMODE(sbuf) & 0777;
			chmod((char *)ttynbuf, 0600);
		}
	}
}

/*
 * Turn off start/stop chars if they aren't the default ^S/^Q.
 * This is so people who make esc their start/stop don't lose.
 * We always turn off quit since datamedias send ^\ for their
 * right arrow key.
 */

void
ttcharoff(void)
{
	/*
	 * use 200 instead of 377 because 377 is y-umlaut
	 * in ISO 8859/1
	 */
	tty.c_cc[VQUIT] = termiosflag ? _POSIX_VDISABLE : '\200';
	if (tty.c_cc[VSTART] != CTRL('q'))
		tty.c_cc[VSTART] = _POSIX_VDISABLE;
	if (tty.c_cc[VSTOP] != CTRL('s'))
		tty.c_cc[VSTOP] = _POSIX_VDISABLE;
	/* We will read ^z and suspend ourselves via kill */
	tty.c_cc[VSUSP] = _POSIX_VDISABLE;
	tty.c_cc[VDSUSP] = _POSIX_VDISABLE;
	tty.c_cc[VREPRINT] = _POSIX_VDISABLE;
	tty.c_cc[VDISCARD] = _POSIX_VDISABLE;
	tty.c_cc[VWERASE] = _POSIX_VDISABLE;
	tty.c_cc[VLNEXT] = _POSIX_VDISABLE;
}

/*
 * Stop open, restoring tty modes.
 */
void
ostop(ttymode f)
{

	pfast = (f.c_oflag & ONLCR) == 0;
	termreset(), fgoto(), flusho();
	normal(f);
	tostop();
}

/* Actions associated with putting the terminal in the right mode. */
void
tostop(void)
{
	putpad((unsigned char *)clr_eos);
	putpad((unsigned char *)cursor_normal);
	putpad((unsigned char *)keypad_local);
	if (!value(vi_MESG) && ttynbuf[0]>1)
		chmod((char *)ttynbuf, ttymesg);
}

#ifndef CBREAK
/*
 * Into cooked mode for interruptibility.
 */
vcook()
{

	tty.sg_flags &= ~RAW;
	sTTY(2);
}

/*
 * Back into raw mode.
 */
vraw()
{

	tty.sg_flags |= RAW;
	sTTY(2);
}
#endif

/*
 * Restore flags to normal state f.
 */
void
normal(ttymode f)
{

	if (normtty > 0) {
		setty(f);
		normtty--;
	}
}

/*
 * Straight set of flags to state f.
 */
ttymode
setty(f)
	ttymode f;
{
	int isnorm = 0;
	ttymode ot;
	ot = tty;

	if (tty.c_lflag & ICANON)
		ttcharoff();
	else
		isnorm = 1;
	tty = f;
	sTTY(2);
	if (!isnorm)
		saveterm();
	return (ot);
}

static struct termio termio;

int
gTTY(int i)
{
	if(termiosflag < 0) {
		if(ioctl(i, TCGETS, &tty) == 0)
			termiosflag = 1;
		else  {
			termiosflag = 0;
			if(ioctl(i, TCGETA, &termio) < 0)
				return (-1);
			tty.c_iflag = termio.c_iflag;
			tty.c_oflag = termio.c_oflag;
			tty.c_cflag = termio.c_cflag;
			tty.c_lflag = termio.c_lflag;
			for(i = 0; i < NCC; i++)
				tty.c_cc[i] = termio.c_cc[i];
		}
		return (0);
	}
	if(termiosflag)
		return (ioctl(i, TCGETS, &tty));
	if(ioctl(i, TCGETA, &termio) < 0)
		return (-1);
	tty.c_iflag = termio.c_iflag;
	tty.c_oflag = termio.c_oflag;
	tty.c_cflag = termio.c_cflag;
	tty.c_lflag = termio.c_lflag;
	for(i = 0; i < NCC; i++)
		tty.c_cc[i] = termio.c_cc[i];
	return (0);
}

/*
 * sTTY: set the tty modes on file descriptor i to be what's
 * currently in global "tty".  (Also use nttyc if needed.)
 */
void
sTTY(int i)
{
	int j;
	if(termiosflag)
		ioctl(i, TCSETSW, &tty);
	else {
		termio.c_iflag = tty.c_iflag;
		termio.c_oflag = tty.c_oflag;
		termio.c_cflag = tty.c_cflag;
		termio.c_lflag = tty.c_lflag;
		for(j = 0; j < NCC; j++)
			termio.c_cc[j] = tty.c_cc[j];
		ioctl(i, TCSETAW, &termio);
	}
}

/*
 * Print newline, or blank if in open/visual
 */
void
noonl(void)
{

	putchar(Outchar != termchar ? ' ' : '\n');
}
