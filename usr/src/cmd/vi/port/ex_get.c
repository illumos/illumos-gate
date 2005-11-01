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

/*
 * Input routines for command mode.
 * Since we translate the end of reads into the implied ^D's
 * we have different flavors of routines which do/don't return such.
 */
static	bool junkbs;
short	lastc = '\n';

void
ignchar(void)
{
	(void)getchar();
}

int
getchar(void)
{
	int c;

	do
		c = getcd();
	while (!globp && c == CTRL('d'));
	return (c);
}

int
getcd(void)
{
	int c;
	extern short slevel;

again:
	c = getach();
	if (c == EOF)
		return (c);
	if (!inopen && slevel==0)
		if (!globp && c == CTRL('d'))
			setlastchar('\n');
		else if (junk(c)) {
			checkjunk(c);
			goto again;
		}
	return (c);
}

int
peekchar(void)
{

	if (peekc == 0)
		peekc = getchar();
	return (peekc);
}

int
peekcd(void)
{
	if (peekc == 0)
		peekc = getcd();
	return (peekc);
}

int verbose;
int
getach(void)
{
	int c, i, prev;
	static unsigned char inputline[128];

	c = peekc;
	if (c != 0) {
		peekc = 0;
		return (c);
	}
	if (globp) {
		if (*globp)
			return (*globp++);
		globp = 0;
		return (lastc = EOF);
	}
top:
	if (input) {
		if(c = *input++)
			return (lastc = c);
		input = 0;
	}
	flush();
	if (intty) {
		c = read(0, inputline, sizeof inputline - 4);
		if (c < 0)
			return (lastc = EOF);
		if (c == 0 || inputline[c-1] != '\n')
			inputline[c++] = CTRL('d');
		if (inputline[c-1] == '\n')
			noteinp();
		prev = 0;
		/* remove nulls from input buffer */
		for (i = 0; i < c; i++)
			if(inputline[i] != 0)
				inputline[prev++] = inputline[i];
		inputline[prev] = 0;
		input = inputline;
		goto top;
	}
	if (read(0, inputline, 1) != 1)
		lastc = EOF;
	else {
		lastc = inputline[0];
		if (verbose)
			write(2, inputline, 1);
	}
	return (lastc);
}

/*
 * Input routine for insert/append/change in command mode.
 * Most work here is in handling autoindent.
 */
static	short	lastin;

int
gettty(void)
{
	int c = 0;
	unsigned char *cp = genbuf;
	unsigned char hadup = 0;
	extern int (*Pline)();
	int offset = Pline == numbline ? 8 : 0;
	int ch;

	if (intty && !inglobal) {
		if (offset) {
			holdcm = 1;
			viprintf("  %4d  ", lineDOT() + 1);
			flush();
			holdcm = 0;
		}
		if (value(vi_AUTOINDENT) ^ aiflag) {
			holdcm = 1;
			if (value(vi_LISP))
				lastin = lindent(dot + 1);
			gotab(lastin + offset);
			while ((c = getcd()) == CTRL('d')) {
				if (lastin == 0 && isatty(0) == -1) {
					holdcm = 0;
					return (EOF);
				}
				lastin = backtab(lastin);
				gotab(lastin + offset);
			}
			switch (c) {

			case '^':
			case '0':
				ch = getcd();
				if (ch == CTRL('d')) {
					if (c == '0')
						lastin = 0;
					if (!over_strike) {
						putchar((int)('\b' | QUOTE));
						putchar((int)(' ' | QUOTE));
						putchar((int)('\b' | QUOTE));
					}
					gotab(offset);
					hadup = 1;
					c = getchar();
				} else
					ungetchar(ch);
				break;

			case '.':
				if (peekchar() == '\n') {
					ignchar();
					noteinp();
					holdcm = 0;
					return (EOF);
				}
				break;

			case '\n':
				hadup = 1;
				break;
			}
		}
		flush();
		holdcm = 0;
	}
	if (c == 0)
		c = getchar();
	while (c != EOF && c != '\n') {
		if (cp > &genbuf[LBSIZE - 2])
			error(gettext("Input line too long"));
		*cp++ = c;
		c = getchar();
	}
	if (c == EOF) {
		if (inglobal)
			ungetchar(EOF);
		return (EOF);
	}
	*cp = 0;
	cp = linebuf;
	if ((value(vi_AUTOINDENT) ^ aiflag) && hadup == 0 && intty && !inglobal) {
		lastin = c = smunch(lastin, genbuf);
		for (c = lastin; c >= value(vi_TABSTOP); c -= value(vi_TABSTOP))
			*cp++ = '\t';
		for (; c > 0; c--)
			*cp++ = ' ';
	}
	CP(cp, genbuf);
	if (linebuf[0] == '.' && linebuf[1] == 0)
		return (EOF);
	return (0);
}

/*
 * Crunch the indent.
 * Hard thing here is that in command mode some of the indent
 * is only implicit, so we must seed the column counter.
 * This should really be done differently so as to use the whitecnt routine
 * and also to hack indenting for LISP.
 */
int
smunch(int col, unsigned char *ocp)
{
	unsigned char *cp;

	cp = ocp;
	for (;;)
		switch (*cp++) {

		case ' ':
			col++;
			continue;

		case '\t':
			col += value(vi_TABSTOP) - (col % value(vi_TABSTOP));
			continue;

		default:
			cp--;
			CP(ocp, cp);
			return (col);
		}
}

unsigned char	*cntrlhm =	(unsigned char *)"^H discarded\n";

void
checkjunk(unsigned char c)
{

	if (junkbs == 0 && c == '\b') {
		write(2, cntrlhm, 13);
		junkbs = 1;
	}
}

void
setin(line *addr)
{

	if (addr == zero)
		lastin = 0;
	else
		getline(*addr), lastin = smunch(0, linebuf);
}
