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
 * Routines to handle structure.
 * Operations supported are:
 *	( ) { } [ ]
 *
 * These cover:		LISP		TEXT
 *	( )		s-exprs		sentences
 *	{ }		list at same	paragraphs
 *	[ ]		defuns		sections
 *
 * { and } for C used to attempt to do something with matching {}'s, but
 * I couldn't find definitions which worked intuitively very well, so I
 * scrapped this.
 *
 * The code here is very hard to understand.
 */
line	*llimit;
int	(*lf)();

int	lindent();

bool	wasend;

int endsent(bool);

/*
 * Find over structure, repeated count times.
 * Don't go past line limit.  F is the operation to
 * be performed eventually.  If pastatom then the user said {}
 * rather than (), implying past atoms in a list (or a paragraph
 * rather than a sentence.
 */
int
lfind(pastatom, cnt, f, limit)
	bool pastatom;
	int cnt, (*f)();
	line *limit;
{
	int c;
	int rc = 0;
	unsigned char save[LBSIZE];

	/*
	 * Initialize, saving the current line buffer state
	 * and computing the limit; a 0 argument means
	 * directional end of file.
	 */
	wasend = 0;
	lf = f;
	strcpy(save, linebuf);
	if (limit == 0)
		limit = dir < 0 ? one : dol;
	llimit = limit;
	wdot = dot;
	wcursor = cursor;

	if (pastatom >= 2) {

 		if (pastatom == 3) {
			while(eend(f) && cnt-- > 0) {
				;
			}
		} else {
			while (cnt > 0 && word(f, cnt))
				cnt--;
		}

		if (dot == wdot) {
			wdot = 0;
			if (cursor == wcursor)
				rc = -1;
		}
	}
	else if (!value(vi_LISP)) {
		unsigned char *icurs;
		line *idot;

		if (linebuf[0] == 0) {
			do
				if (!lnext())
					goto ret;
			while (linebuf[0] == 0);
			if (dir > 0) {
				wdot--;
				linebuf[0] = 0;
				wcursor = linebuf;
				/*
				 * If looking for sentence, next line
				 * starts one.
				 */
				if (!pastatom) {
					icurs = wcursor;
					idot = wdot;
					goto begin;
				}
			}
		}
		icurs = wcursor;
		idot = wdot;

		/*
		 * Advance so as to not find same thing again.
		 */
		if (dir > 0) {
			if (!lnext()) {
				rc = -1;
				goto ret;
			}
#ifdef XPG4
		} else {
			if (!lnext()) {
				rc = -1;
				goto ret;
			}
			(void) ltosol1("");
		}
#else /* ! XPG4 */
		} else
			(void)lskipa1("");
#endif /* XPG4 */

		/*
		 * Count times find end of sentence/paragraph.
		 */
begin:
		for (;;) {
			while (!endsent(pastatom))
				if (!lnext())
					goto ret;
			if (!pastatom || wcursor == linebuf && endPS())
				if (--cnt <= 0)
					break;
			if (linebuf[0] == 0) {
				do
					if (!lnext())
						goto ret;
				while (linebuf[0] == 0);
			} else
				if (!lnext())
					goto ret;
		}

		/*
		 * If going backwards, and didn't hit the end of the buffer,
		 * then reverse direction.
		 */
		if (dir < 0 && (wdot != llimit || wcursor != linebuf)) {
			dir = 1;
			llimit = dot;
			/*
			 * Empty line needs special treatement.
			 * If moved to it from other than beginning of next line,
			 * then a sentence starts on next line.
			 */
			if (linebuf[0] == 0 && !pastatom &&
			   (wdot != dot - 1 || cursor != linebuf)) {
				(void) lnext();
				goto ret;
			}
		}

		/*
		 * If we are not at a section/paragraph division,
		 * advance to next.
		 */
		if (wcursor == icurs && wdot == idot || wcursor != linebuf || !endPS())
			(void)lskipa1("");
	}
	else {
		c = *wcursor;
		/*
		 * Startup by skipping if at a ( going left or a ) going
		 * right to keep from getting stuck immediately.
		 */
		if (dir < 0 && c == '(' || dir > 0 && c == ')') {
			if (!lnext()) {
				rc = -1;
				goto ret;
			}
		}
		/*
		 * Now chew up repetition count.  Each time around
		 * if at the beginning of an s-exp (going forwards)
		 * or the end of an s-exp (going backwards)
		 * skip the s-exp.  If not at beg/end resp, then stop
		 * if we hit a higher level paren, else skip an atom,
		 * counting it unless pastatom.
		 */
		while (cnt > 0) {
			c = *wcursor;
			if (dir < 0 && c == ')' || dir > 0 && c == '(') {
				if (!lskipbal("()"))
					goto ret;
				/*
 				 * Unless this is the last time going
				 * backwards, skip past the matching paren
				 * so we don't think it is a higher level paren.
				 */
				if (dir < 0 && cnt == 1)
					goto ret;
				if (!lnext() || !ltosolid())
					goto ret;
				--cnt;
			} else if (dir < 0 && c == '(' || dir > 0 && c == ')')
				/* Found a higher level paren */
				goto ret;
			else {
				if (!lskipatom())
					goto ret;
				if (!pastatom)
					--cnt;
			}
		}
	}
ret:
	strcLIN(save);
	return (rc);
}

/*
 * Is this the end of a sentence?
 */
int
endsent(bool pastatom)
{
	unsigned char *cp = wcursor;
	int c, d;
	int	len;

	/*
	 * If this is the beginning of a line, then
	 * check for the end of a paragraph or section.
	 */
	if (cp == linebuf)
		return (endPS());

	/*
	 * Sentences end with . ! ? not at the beginning
	 * of the line, and must be either at the end of the line,
	 * or followed by 2 spaces.  Any number of intervening ) ] ' "
	 * characters are allowed.
	 */
	if (!any(c = *cp, ".!?"))
		goto tryps;

	do {
		if ((len = mblen((char *)cp, MB_CUR_MAX)) <= 0)
			len = 1;
		cp += len;
		if ((d = *cp) == 0)
			return (1);
#ifdef XPG4
	} while (any(d, ")]'\""));
#else /* ! XPG4 */
	} while (any(d, ")]'"));
#endif /* XPG4 */
	if (*cp == 0 || *cp++ == ' ' && *cp == ' ')
		return (1);
tryps:
	if (cp[1] == 0)
		return (endPS());
	return (0);
}

/*
 * End of paragraphs/sections are respective
 * macros as well as blank lines and form feeds.
 */
int
endPS(void)
{

	return (linebuf[0] == 0 ||
#ifdef XPG4
		/* POSIX 1003.2 Section 5.35.7.1: control-L, "{"	*/
		linebuf[0] == '{' ||
		linebuf[0] == CTRL('L') ||
#endif /* XPG4 */
		isa(svalue(vi_PARAGRAPHS)) || isa(svalue(vi_SECTIONS)));

}

int
lindent(line *addr)
{
	int i;
	unsigned char *swcurs = wcursor;
	line *swdot = wdot;

again:
	if (addr > one) {
		unsigned char *cp;
		int cnt = 0;

		addr--;
		getaline(*addr);
		for (cp = linebuf; *cp; cp++)
			if (*cp == '(')
				cnt++;
			else if (*cp == ')')
				cnt--;
		cp = vpastwh(linebuf);
		if (*cp == 0)
			goto again;
		if (cnt == 0)
			return (whitecnt(linebuf));
		addr++;
	}
	wcursor = linebuf;
	linebuf[0] = 0;
	wdot = addr;
	dir = -1;
	llimit = one;
	lf = lindent;
	if (!lskipbal("()"))
		i = 0;
	else if (wcursor == linebuf)
		i = 2;
	else {
		unsigned char *wp = wcursor;

		dir = 1;
		llimit = wdot;
		if (!lnext() || !ltosolid() || !lskipatom()) {
			wcursor = wp;
			i = 1;
		} else
			i = 0;
		i += column(wcursor) - 1;
		if (!inopen)
			i--;
	}
	wdot = swdot;
	wcursor = swcurs;
	return (i);
}

int
lmatchp(line *addr)
{
	int i;
	unsigned char *parens, *cp;

	for (cp = cursor; !any(*cp, "({[)}]");) {
		if (*cp == 0)
			return (0);
		if ((i = mblen((char *)cp, MB_CUR_MAX)) <= 0)
			i = 1;
		cp += i;
	}

	lf = 0;
	parens = any(*cp, "()") ? (unsigned char *)"()" : any(*cp, "[]") ? (unsigned char *)"[]" : (unsigned char *)"{}";
	if (*cp == parens[1]) {
		dir = -1;
		llimit = one;
	} else {
		dir = 1;
		llimit = dol;
	}
	if (addr)
		llimit = addr;
	if (splitw)
		llimit = dot;
	wcursor = cp;
	wdot = dot;
	i = lskipbal(parens);
	return (i);
}

void
lsmatch(unsigned char *cp)
{
	unsigned char save[LBSIZE];
	unsigned char *sp = save;
	unsigned char *scurs = cursor;

	wcursor = cp;
	strcpy(sp, linebuf);
	*wcursor = 0;
	strcpy(cursor, genbuf);
	cursor = strend(linebuf);
	cursor = lastchr(linebuf, cursor);
	if (lmatchp(dot - vcline)) {
		int i = insmode;
		int c = outcol;
		int l = outline;

		if (!move_insert_mode)
			endim();
		vgoto(splitw ? WECHO : LINE(wdot - llimit), column(wcursor) - 1);
		flush();
		sleep(1);
		vgoto(l, c);
		if (i)
			goim();
	}
	else {
		strcLIN(sp);
		strcpy(scurs, genbuf);
		if (!lmatchp((line *) 0))
			(void) beep();
	}
	strcLIN(sp);
	wdot = 0;
	wcursor = 0;
	cursor = scurs;
}

int
ltosolid(void)
{

	return (ltosol1("()"));
}

int
ltosol1(unsigned char *parens)
{
	unsigned char *cp;
	int	len;
	unsigned char	*ocp;

	if (*parens && !*wcursor && !lnext())
		return (0);

	while (isspace(*wcursor) || (*wcursor == 0 && *parens))
		if (!lnext())
			return (0);
	if (any(*wcursor, parens) || dir > 0)
		return (1);

	ocp = linebuf;
	for (cp = linebuf; cp < wcursor; cp += len) {
		if (isascii(*cp)) {
			len = 1;
			if (isspace(*cp) || any(*cp, parens))
				ocp = cp + 1;
			continue;
		}
		if ((len = mblen((char *)cp, MB_CUR_MAX)) <= 0)
			len = 1;
	}
	wcursor = ocp;
	return (1);
}

int
lskipbal(unsigned char *parens)
{
	int level = dir;
	int c;

	do {
		if (!lnext()) {
			wdot = NOLINE;
			return (0);
		}
		c = *wcursor;
		if (c == parens[1])
			level--;
		else if (c == parens[0])
			level++;
	} while (level);
	return (1);
}

int
lskipatom(void)
{

	return (lskipa1("()"));
}

int
lskipa1(unsigned char *parens)
{
	int c;

	for (;;) {
		if (dir < 0 && wcursor == linebuf) {
			if (!lnext())
				return (0);
			break;
		}
		c = *wcursor;
		if (c && (isspace(c) || any(c, parens)))
			break;

		if (!lnext())
			return (0);
		if (dir > 0 && wcursor == linebuf)
			break;
	}
	return (ltosol1(parens));
}

int
lnext(void)
{

	if (dir > 0) {
		if (*wcursor)
			wcursor = nextchr(wcursor);
		if (*wcursor)
			return (1);
		if (wdot >= llimit) {
			if (lf == vmove && wcursor > linebuf)
				wcursor = lastchr(linebuf, wcursor);
			return (0);
		}
		wdot++;
		getaline(*wdot);
		wcursor = linebuf;
		return (1);
	} else {
		wcursor = lastchr(linebuf, wcursor);
		if (wcursor >= linebuf)
			return (1);
		if (lf == lindent && linebuf[0] == '(')
			llimit = wdot;
		if (wdot <= llimit) {
			wcursor = linebuf;
			return (0);
		}
		wdot--;
		getaline(*wdot);
		if(!*linebuf)
			wcursor = linebuf;
		else {
			wcursor = strend(linebuf);
			wcursor = lastchr(linebuf, wcursor);
		}
		return (1);
	}
}

int
lbrack(int c, int (*f)())
{
	line *addr;

	addr = dot;
	for (;;) {
		addr += dir;
		if (addr < one || addr > dol) {
			addr -= dir;
			break;
		}
		getaline(*addr);
		if (linebuf[0] == '{' ||
#ifdef XPG4
		    /* POSIX 1003.2 Section 5.35.7.1: control-L		*/
		    linebuf[0] == CTRL('L') ||
#endif /* XPG4 */
		    value(vi_LISP) && linebuf[0] == '(' ||
		    isa(svalue(vi_SECTIONS))) {
			if (c == ']' && f != vmove) {
				addr--;
				getaline(*addr);
			}
			break;
		}
		if (c == ']' && f != vmove && linebuf[0] == '}')
			break;
	}
	if (addr == dot)
		return (0);
	if (f != vmove)
		wcursor = c == ']' ? strend(linebuf) : linebuf;
	else
		wcursor = 0;
	wdot = addr;
	vmoving = 0;
	return (1);
}

int
isa(unsigned char *cp)
{

	if (linebuf[0] != '.')
		return (0);
	for (; cp[0] && cp[1]; cp += 2)
		if (linebuf[1] == cp[0]) {
			if (linebuf[2] == cp[1])
				return (1);
			if (linebuf[2] == 0 && cp[1] == ' ')
				return (1);
		}
	return (0);
}
