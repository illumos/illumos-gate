/*
 * Copyright 1997 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * Copyright (c) 1980 Regents of the University of California.
 * All rights reserved.  The Berkeley software License Agreement
 * specifies the terms and conditions for redistribution.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*LINTLIBRARY*/

#if 0
static char
sccsid[] = "@(#)termcap.c 1.11 88/02/08 SMI"; /* from UCB 5.1 6/5/85 */
#endif

#define	BUFSIZ		1024
#define	MAXHOP		32	/* max number of tc= indirections */
#define	E_TERMCAP	"/etc/termcap"

#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <strings.h>
#include <ctype.h>

/*
 * termcap - routines for dealing with the terminal capability data base
 *
 * BUG:		Should use a "last" pointer in tbuf, so that searching
 *		for capabilities alphabetically would not be a n**2/2
 *		process when large numbers of capabilities are given.
 * Note:	If we add a last pointer now we will screw up the
 *		tc capability. We really should compile termcap.
 *
 * Essentially all the work here is scanning and decoding escapes
 * in string capabilities.  We don't use stdio because the editor
 * doesn't, and because living w/o it is not hard.
 */

static	char *tbuf;
static	int hopcount;	/* detect infinite loops in termcap, init 0 */

/* forward declarations */
static char *tdecode(char *, char **);
static void tngetsize(char *);
static char *tskip(char *bp);
static char *appendsmalldec(char *, int);
int tnamatch(char *);
int tnchktc(void);

/*
 * Get an entry for terminal name in buffer bp,
 * from the termcap file.  Parse is very rudimentary;
 * we just notice escaped newlines.
 */

int
tgetent(char *bp, char *name)
{
	char *cp;
	int c;
	int i = 0;
	ssize_t cnt = 0;
	char ibuf[BUFSIZ];
	int tf;

	tbuf = bp;
	tf = -1;
#ifndef V6
	cp = getenv("TERMCAP");
	/*
	 * TERMCAP can have one of two things in it. It can be the
	 * name of a file to use instead of /etc/termcap. In this
	 * case it better start with a "/". Or it can be an entry to
	 * use so we don't have to read the file. In this case it
	 * has to already have the newlines crunched out.
	 */
	if (cp && *cp) {
		if (*cp == '/') {
			tf = open(cp, 0);
		} else {
			tbuf = cp;
			c = tnamatch(name);
			tbuf = bp;
			if (c) {
				(void) strcpy(bp, cp);
				return (tnchktc());
			}
		}
	}
	if (tf < 0)
		tf = open(E_TERMCAP, 0);
#else
	tf = open(E_TERMCAP, 0);
#endif
	if (tf < 0)
		return (-1);
	for (;;) {
		cp = bp;
		for (;;) {
			if (i == cnt) {
				cnt = read(tf, ibuf, BUFSIZ);
				if (cnt <= 0) {
					(void) close(tf);
					return (0);
				}
				i = 0;
			}
			c = ibuf[i++];
			if (c == '\n') {
				if (cp > bp && cp[-1] == '\\') {
					cp--;
					continue;
				}
				break;
			}
			if (cp >= bp+BUFSIZ) {
				(void) write(2, "Termcap entry too long\n", 23);
				break;
			} else
				*cp++ = (char) c;
		}
		*cp = 0;

		/*
		 * The real work for the match.
		 */
		if (tnamatch(name)) {
			(void) close(tf);
			return (tnchktc());
		}
	}
}

/*
 * tnchktc: check the last entry, see if it's tc=xxx. If so,
 * recursively find xxx and append that entry (minus the names)
 * to take the place of the tc=xxx entry. This allows termcap
 * entries to say "like an HP2621 but doesn't turn on the labels".
 * Note that this works because of the left to right scan.
 */

int
tnchktc(void)
{
	char *p, *q;
	char tcname[16];	/* name of similar terminal */
	char tcbuf[BUFSIZ];
	char *holdtbuf = tbuf;
	ptrdiff_t l;

	p = tbuf + strlen(tbuf) - 2;	/* before the last colon */
	while (*--p != ':')
		if (p < tbuf) {
			(void) write(2, "Bad termcap entry\n", 18);
			return (0);
		}
	p++;
	/* p now points to beginning of last field */
	if (p[0] != 't' || p[1] != 'c') {
		tngetsize(tbuf);
		return (1);
	}
	(void) strcpy(tcname, p+3);
	q = tcname;
	while (*q && *q != ':')
		q++;
	*q = 0;
	if (++hopcount > MAXHOP) {
		(void) write(2, "Infinite tc= loop\n", 18);
		return (0);
	}
	if (tgetent(tcbuf, tcname) != 1) {
		hopcount = 0;		/* unwind recursion */
		return (0);
	}
	for (q = tcbuf; *q != ':'; q++)
		;
	l = p - holdtbuf + strlen(q);
	if (l > BUFSIZ) {
		(void) write(2, "Termcap entry too long\n", 23);
		q[BUFSIZ - (p-tbuf)] = 0;
	}
	(void) strcpy(p, q+1);
	tbuf = holdtbuf;
	hopcount = 0;			/* unwind recursion */
	tngetsize(tbuf);
	return (1);
}

/*
 * Tnamatch deals with name matching.  The first field of the termcap
 * entry is a sequence of names separated by |'s, so we compare
 * against each such name.  The normal : terminator after the last
 * name (before the first field) stops us.
 */

int
tnamatch(char *np)
{
	char *Np, *Bp;

	Bp = tbuf;
	if (*Bp == '#')
		return (0);
	for (;;) {
		for (Np = np; *Np && *Bp == *Np; Bp++, Np++)
			continue;
		if (*Np == 0 && (*Bp == '|' || *Bp == ':' || *Bp == 0))
			return (1);
		while (*Bp && *Bp != ':' && *Bp != '|')
			Bp++;
		if (*Bp == 0 || *Bp == ':')
			return (0);
		Bp++;
	}
}

/*
 * Skip to the next field.  Notice that this is very dumb, not
 * knowing about \: escapes or any such.  If necessary, :'s can be put
 * into the termcap file in octal.
 */

static char *
tskip(char *bp)
{

	while (*bp && *bp != ':')
		bp++;
	if (*bp == ':') {
		do {
			bp++;
			while (isspace(*bp))
				bp++;
		} while (*bp == ':');
	}
	return (bp);
}

/*
 * Return the (numeric) option id.
 * Numeric options look like
 *	li#80
 * i.e. the option string is separated from the numeric value by
 * a # character.  If the option is not found we return -1.
 * Note that we handle octal numbers beginning with 0.
 */

int
tgetnum(char *id)
{
	int i, base;
	char *bp = tbuf;

	for (;;) {
		bp = tskip(bp);
		if (*bp == 0)
			return (-1);
		if (*bp++ != id[0] || *bp == 0 || *bp++ != id[1])
			continue;
		if (*bp == '@')
			return (-1);
		if (*bp != '#')
			continue;
		bp++;
		base = 10;
		if (*bp == '0')
			base = 8;
		i = 0;
		while (isdigit(*bp))
			i *= base, i += *bp++ - '0';
		return (i);
	}
}

/*
 * Handle a flag option.
 * Flag options are given "naked", i.e. followed by a : or the end
 * of the buffer.  Return 1 if we find the option, or 0 if it is
 * not given.
 */

int
tgetflag(char *id)
{
	char *bp = tbuf;

	for (;;) {
		bp = tskip(bp);
		if (!*bp)
			return (0);
		if (*bp++ == id[0] && *bp != 0 && *bp++ == id[1]) {
			if (!*bp || *bp == ':')
				return (1);
			else if (*bp == '@')
				return (0);
		}
	}
}

/*
 * Get a string valued option.
 * These are given as
 *	cl=^Z
 * Much decoding is done on the strings, and the strings are
 * placed in area, which is a ref parameter which is updated.
 * No checking on area overflow.
 */

char *
tgetstr(char *id, char **area)
{
	char *bp = tbuf;

	for (;;) {
		bp = tskip(bp);
		if (!*bp)
			return (0);
		if (*bp++ != id[0] || *bp == 0 || *bp++ != id[1])
			continue;
		if (*bp == '@')
			return (0);
		if (*bp != '=')
			continue;
		bp++;
		return (tdecode(bp, area));
	}
}

/*
 * Tdecode does the grung work to decode the
 * string capability escapes.
 */

static char *
tdecode(char *str, char **area)
{
	char *cp;
	int c;
	char *dp;
	int i;

	cp = *area;
	while (((c = *str++) != 0) && c != ':') {
		switch (c) {

		case '^':
			c = *str++ & 037;
			break;

		case '\\':
			dp = "E\033^^\\\\::n\nr\rt\tb\bf\f";
			c = *str++;
nextc:
			if (*dp++ == c) {
				c = *dp++;
				break;
			}
			dp++;
			if (*dp)
				goto nextc;
			if (isdigit(c)) {
				c -= '0', i = 2;
				do
					c <<= 3, c |= *str++ - '0';
				while (--i && isdigit(*str));
			}
			break;
		}
		*cp++ = (char) c;
	}
	*cp++ = 0;
	str = *area;
	*area = cp;
	return (str);
}

#include <sys/ioctl.h>

static void
tngetsize(char *bp)
{
	struct winsize ws;
	char *np, *cp;

	if (ioctl(1, TIOCGWINSZ, (char *)&ws) < 0)
		return;
	if (ws.ws_row == 0 || ws.ws_col == 0 ||
	    ws.ws_row > 999 || ws.ws_col > 999)
		return;
	cp = index(bp, ':');	/* find start of description */
	bp = rindex(bp, 0);	/* find end of description */
	np = bp + 15;		/* allow enough room for stuff below */
	while (bp >= cp)	/* move description right 15 chars */
		*np-- = *bp--;
	bp++;			/* bp now points to where ':' used to be */
	*bp++ = ':';
	*bp++ = 'l';
	*bp++ = 'i';
	*bp++ = '#';
	bp = appendsmalldec(bp, ws.ws_row);
	*bp++ = ':';
	*bp++ = 'c';
	*bp++ = 'o';
	*bp++ = '#';
	bp = appendsmalldec(bp, ws.ws_col);
	*bp++ = ':';
	while (bp <= np)	/* space fill to start of orig description */
		*bp++ = ' ';
}

static char *
appendsmalldec(char *bp, int val)
{
	int	i;

	if ((i = val / 100) != 0) {
		*bp++ = '0' + i;
		val %= 100;
		if (0 == val / 10)
			*bp++ = '0'; /* place holder because next test fails */
	}
	if ((i = val / 10) != 0)
		*bp++ = '0' + i;
	*bp++ = '0' + val % 10;
	return (bp);
}
