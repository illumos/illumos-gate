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
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

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

/*
n10.c

Device interfaces
*/

#include <limits.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#ifdef EUC
#ifdef NROFF
#include <stdlib.h>
#endif /* NROFF */
#endif /* EUC */
#include "tdef.h"
#include "ext.h"
#include "tw.h"

struct t t;	/* terminal characteristics */

int	dtab;
int	plotmode;
int	esct;

char	xchname[4 * (NROFFCHARS-_SPECCHAR_ST)];	/* hy, em, etc. */
short	xchtab[NROFFCHARS-_SPECCHAR_ST];		/* indexes into chname[] */
char	*codestr;
char	*chname = xchname;
short	*chtab = xchtab;
int	nchtab = 0;


int	Inch;
int	Hor;
int	Vert;
int	nfonts	= 4;	/* R, I, B, S */

/* these characters are used as various signals or values
 * in miscellaneous places.
 * values are set in specnames in t10.c
 */

int	c_hyphen;
int	c_emdash;
int	c_rule;
int	c_minus;
int	c_fi;
int	c_fl;
int	c_ff;
int	c_ffi;
int	c_ffl;
int	c_acute;
int	c_grave;
int	c_under;
int	c_rooten;
int	c_boxrule;
int	c_lefthand;
int	c_dagger;
int	c_isalnum;

int
ptinit()
{
	int i, j;
	char *p, *cp, *q;
	int nread, fd;
	extern char *skipstr(), *getstr(), *getint();
	extern char *setbrk();
	struct stat stbuf;
	char check[50];

	strcat(termtab, devname);
	if ((fd = open(termtab, 0)) < 0) {
		errprint(gettext("cannot open %s"), termtab);
		exit(-1);
	}

	fstat(fd, &stbuf);
	codestr = setbrk((int) stbuf.st_size);

	nread = read(fd, codestr, (int) stbuf.st_size);
	close(fd);

	p = codestr;
	p = skipstr(p);		/* skip over type, could check */
	p = skipstr(p); p = getint(p, &t.bset);
	p = skipstr(p); p = getint(p, &t.breset);
	p = skipstr(p); p = getint(p, &t.Hor);
	p = skipstr(p); p = getint(p, &t.Vert);
	p = skipstr(p); p = getint(p, &t.Newline);
	p = skipstr(p); p = getint(p, &t.Char);
	p = skipstr(p); p = getint(p, &t.Em);
	p = skipstr(p); p = getint(p, &t.Halfline);
	p = skipstr(p); p = getint(p, &t.Adj);
	p = skipstr(p); p = getstr(p, t.twinit = p);
	p = skipstr(p); p = getstr(p, t.twrest = p);
	p = skipstr(p); p = getstr(p, t.twnl = p);
	p = skipstr(p); p = getstr(p, t.hlr = p);
	p = skipstr(p); p = getstr(p, t.hlf = p);
	p = skipstr(p); p = getstr(p, t.flr = p);
	p = skipstr(p); p = getstr(p, t.bdon = p);
	p = skipstr(p); p = getstr(p, t.bdoff = p);
	p = skipstr(p); p = getstr(p, t.iton = p);
	p = skipstr(p); p = getstr(p, t.itoff = p);
	p = skipstr(p); p = getstr(p, t.ploton = p);
	p = skipstr(p); p = getstr(p, t.plotoff = p);
	p = skipstr(p); p = getstr(p, t.up = p);
	p = skipstr(p); p = getstr(p, t.down = p);
	p = skipstr(p); p = getstr(p, t.right = p);
	p = skipstr(p); p = getstr(p, t.left = p);

	getstr(p, check);
	if (strcmp(check, "charset") != 0) {
		errprint(gettext("device table apparently curdled"));
		exit(1);
	}

	for (i = 0; i < _SPECCHAR_ST; i++)
		t.width[i] = 1;	/* default widths */

	i = 0;
/* this ought to be a pointer array and in place in codestr */
	cp = chname + 1;	/* bug if starts at 0, in setch */
	while (p < codestr + nread) {
		while (*p == ' ' || *p == '\t' || *p == '\n')
			p++;
		if (i + _SPECCHAR_ST >= NROFFCHARS) {
			errprint(gettext("too many names in charset for %s"),
					 termtab);
			exit(1);
		}
		chtab[i] = cp - chname;	/* index, not pointer */
		*cp++ = *p++;	/* 2-char names */
		*cp++ = *p++;
		*cp++ = '\0';
		while (*p == ' ' || *p == '\t')
			p++;
		t.width[i+_SPECCHAR_ST] = *p++ - '0';
		while (*p == ' ' || *p == '\t')
			p++;
		t.codetab[i] = p;
		p = getstr(p, p);	/* compress string */
		p++;
		i++;
		nchtab++;
	}

	sps = EM;
	ics = EM * 2;
	dtab = 8 * t.Em;
	for (i = 0; i < 16; i++)
		tabtab[i] = dtab * (i + 1);
	pl = 11 * INCH;
	po = PO;
	spacesz = SS;
	lss = lss1 = VS;
	ll = ll1 = lt = lt1 = LL;
	smnt = nfonts = 5;	/* R I B BI S */
	specnames();	/* install names like "hyphen", etc. */
	if (eqflg)
		t.Adj = t.Hor;

	return (0);
}

char *skipstr(s)	/* skip over leading space plus string */
	char *s;
{
	while (*s == ' ' || *s == '\t' || *s == '\n')
		s++;
	while (*s != ' ' && *s != '\t' && *s != '\n')
		if (*s++ == '\\')
			s++;
	return s;
}

char *getstr(s, t)	/* find next string in s, copy to t */
	char *s, *t;
{
	int quote = 0;

	while (*s == ' ' || *s == '\t' || *s == '\n')
		s++;
	if (*s == '"') {
		s++;
		quote = 1;
	}
	for (;;) {
		if (quote && *s == '"') {
			s++;
			break;
		}
		if (!quote && (*s == ' ' || *s == '\t' || *s == '\n'))
			break;
		if (*s != '\\')
			*t++ = *s++;
		else {
			s++;	/* skip \\ */
			if (isdigit((unsigned char)s[0]) &&
			    isdigit((unsigned char)s[1]) &&
			    isdigit((unsigned char)s[2])) {
				*t++ = (s[0]-'0')<<6 | (s[1]-'0')<<3 | s[2]-'0';
				s += 2;
			} else if (isdigit((unsigned char)s[0])) {
				*t++ = *s - '0';
			} else if (*s == 'b') {
				*t++ = '\b';
			} else if (*s == 'n') {
				*t++ = '\n';
			} else if (*s == 'r') {
				*t++ = '\r';
			} else if (*s == 't') {
				*t++ = '\t';
			} else {
				*t++ = *s;
			}
			s++;
		}
	}
	*t = '\0';
	return s;
}

char *getint(s, pn)	/* find integer at s */
	char *s;
	int *pn;
{
	int base;

	while (*s == ' ' || *s == '\t' || *s == '\n')
		s++;
	base = (*s == '0') ? 8 : 10;
	*pn = 0;
	while (isdigit((unsigned char)*s))
		*pn = base * *pn + *s++ - '0';
	return s;
}

int
specnames()
{
	static struct {
		int	*n;
		char	*v;
	} spnames[] = {
		&c_hyphen, "hy",
		&c_emdash, "em",
		&c_rule, "ru",
		&c_minus, "\\-",
		&c_fi, "fi",
		&c_fl, "fl",
		&c_ff, "ff",
		&c_ffi, "Fi",
		&c_ffl, "Fl",
		&c_acute, "aa",
		&c_grave, "ga",
		&c_under, "ul",
		&c_rooten, "rn",
		&c_boxrule, "br",
		&c_lefthand, "lh",
		&c_isalnum, "__",
		0, 0
	};
	int	i;

	for (i = 0; spnames[i].n; i++)
		*spnames[i].n = findch(spnames[i].v);
	if (c_isalnum == 0)
		c_isalnum = NROFFCHARS;

	return (0);
}


int
findch(s)	/* find char s in chname */
char	*s;
{
	int	i;

	for (i = 0; chtab[i] != 0; i++)
		if (strcmp(s, &chname[chtab[i]]) == 0)
			return(i + _SPECCHAR_ST);
	return(0);
}

int
twdone()
{
	int waitf;

	obufp = obuf;
	if (t.twrest)		/* has ptinit() been done yet? */
		oputs(t.twrest);
	flusho();
	if (pipeflg) {
		close(ptid);
		wait(&waitf);
	}
	restore_tty();

	return (0);
}


int
ptout(i)
	tchar i;
{
	*olinep++ = i;
	if (olinep >= &oline[LNSIZE])
		olinep--;
	if (cbits(i) != '\n')
		return (0);
	olinep--;
	lead += dip->blss + lss - t.Newline;
	dip->blss = 0;
	esct = esc = 0;
	if (olinep > oline) {
		move();
		ptout1();
		oputs(t.twnl);
	} else {
		lead += t.Newline;
		move();
	}
	lead += dip->alss;
	dip->alss = 0;
	olinep = oline;

	return (0);
}


int
ptout1()
{
	int	k;
	char	*codep;
#ifdef EUC
#ifdef NROFF
	int cnt;
	tchar *qq;
#endif /* NROFF */
#endif /* EUC */
	extern char	*plot();
	int	w, j, phyw;
#ifdef EUC
#ifdef NROFF
	int jj;
#endif /* NROFF */
#endif /* EUC */
	tchar * q, i;
	static int oxfont = FT;	/* start off in roman */

	for (q = oline; q < olinep; q++) {
		i = *q;
		if (ismot(i)) {
			j = absmot(i);
			if (isnmot(i))
				j = -j;
			if (isvmot(i))
				lead += j;
			else 
				esc += j;
			continue;
		}
		if ((k = cbits(i)) <= 040) {
			switch (k) {
			case ' ': /*space*/
				esc += t.Char;
				break;
			case '\033':
			case '\007':
			case '\016':
			case '\017':
				oput(k);
				break;
			}
			continue;
		}
#ifdef EUC
#ifdef NROFF
		if (multi_locale && ((k & MBMASK) || (k & CSMASK))) {
			cnt = 0;
			while ((*q & MBMASK1) && (cnt + 1 < (int)MB_CUR_MAX)) {
				cnt++;
				q++;
			}
			if ((cnt && !(*q & CSMASK)) || (*q & MBMASK1)) {
				q -= cnt;
				cnt = 0;
				*q &= ~0xfe00;
			}
			k = cbits(i = *q);
			phyw = w = t.Char * csi_width[cs(i)];
		} else {
#endif /* NROFF */
#endif /* EUC */
		phyw = w = t.Char * t.width[k];
		if (iszbit(i))
			w = 0;
#ifdef EUC
#ifdef NROFF
		}
#endif /* NROFF */
#endif /* EUC */
		if (esc || lead)
			move();
		esct += w;
#ifndef EUC
		xfont = fbits(i);
#else
#ifndef NROFF
		xfont = fbits(i);
#else
#endif /* NROFF */
		xfont = (fbits(*q) % NFONT);	/* for invalid code */
#endif /* EUC */
		if (xfont != oxfont) {
			if (oxfont == ulfont || oxfont == BIFONT)
				oputs(t.itoff);
			if (bdtab[oxfont])
				oputs(t.bdoff);
			if (xfont == ulfont || xfont == BIFONT)
				oputs(t.iton);
			if (bdtab[xfont])
				oputs(t.bdon);
			oxfont = xfont;
		}
		if ((xfont == ulfont || xfont == BIFONT) && !(*t.iton & 0377)) {
			for (j = w / t.Char; j > 0; j--)
				oput('_');
			for (j = w / t.Char; j > 0; j--)
				oput('\b');
		}
		if ((j = bdtab[xfont]) && !(*t.bdon & 0377))
			j++;
		else
			j = 1;	/* number of overstrikes for bold */
		if (k < 128) {	/* ordinary ascii */
			oput(k);
			while (--j > 0) {
				oput('\b');
				oput(k);
			}
#ifdef EUC
#ifdef NROFF
		} else if (multi_locale && (k & CSMASK)) {
			for (qq = q - cnt; qq <= q;)
				oput(cbits(*qq++));
			while (--j > 0) {
				for (jj = cnt + 1; jj > 0; jj--)
					oput('\b');
				for (qq = q - cnt; qq <= q;)
					oput(cbits(*qq++));
			}
		} else if (k < 256) {
			/*
			 * Invalid character for C locale or
			 * non-printable 8-bit single byte
			 * character such as <no-break-sp>
			 * in ISO-8859-1
			 */
			oput(k);
			while (--j > 0) {
				oput('\b');
				oput(k);
			}
#endif /* NROFF */
#endif /* EUC */
		} else if (k >= nchtab + _SPECCHAR_ST) {
			oput(k - nchtab - _SPECCHAR_ST);
		} else {
			int oj = j;
			codep = t.codetab[k-_SPECCHAR_ST];
			while (*codep != 0) {
				if (*codep & 0200) {
					codep = plot(codep);
					oput(' ');
				} else {
					if (*codep == '%')	/* escape */
						codep++;
					oput(*codep);
					if (*codep == '\033')
						oput(*++codep);
					else if (*codep != '\b')
						for (j = oj; --j > 0; ) {
							oput('\b');
							oput(*codep);
						}
					codep++;
				}
			}
		}
		if (!w)
			for (j = phyw / t.Char; j > 0; j--)
				oput('\b');
	}

	return (0);
}


char	*plot(x)
char	*x;
{
	int	i;
	char	*j, *k;

	oputs(t.ploton);
	k = x;
	if ((*k & 0377) == 0200)
		k++;
	for (; *k; k++) {
		if (*k == '%') {	/* quote char within plot mode */
			oput(*++k);
		} else if (*k & 0200) {
			if (*k & 0100) {
				if (*k & 040)
					j = t.up; 
				else 
					j = t.down;
			} else {
				if (*k & 040)
					j = t.left; 
				else 
					j = t.right;
			}
			if ((i = *k & 037) == 0) {	/* 2nd 0200 turns it off */
				++k;
				break;
			}
			while (i--)
				oputs(j);
		} else 
			oput(*k);
	}
	oputs(t.plotoff);
	return(k);
}


int
move()
{
	int	k;
	char	*i, *j;
	char	*p, *q;
	int	iesct, dt;

	iesct = esct;
	if (esct += esc)
		i = "\0"; 
	else 
		i = "\n\0";
	j = t.hlf;
	p = t.right;
	q = t.down;
	if (lead) {
		if (lead < 0) {
			lead = -lead;
			i = t.flr;
			/*	if(!esct)i = t.flr; else i = "\0";*/
			j = t.hlr;
			q = t.up;
		}
		if (*i & 0377) {
			k = lead / t.Newline;
			lead = lead % t.Newline;
			while (k--)
				oputs(i);
		}
		if (*j & 0377) {
			k = lead / t.Halfline;
			lead = lead % t.Halfline;
			while (k--)
				oputs(j);
		} else { /* no half-line forward, not at line begining */
			k = lead / t.Newline;
			lead = lead % t.Newline;
			if (k > 0) 
				esc = esct;
			i = "\n";
			while (k--) 
				oputs(i);
		}
	}
	if (esc) {
		if (esc < 0) {
			esc = -esc;
			j = "\b";
			p = t.left;
		} else {
			j = " ";
			if (hflg)
				while ((dt = dtab - (iesct % dtab)) <= esc) {
					if (dt % t.Em)
						break;
					oput(TAB);
					esc -= dt;
					iesct += dt;
				}
		}
		k = esc / t.Em;
		esc = esc % t.Em;
		while (k--)
			oputs(j);
	}
	if ((*t.ploton & 0377) && (esc || lead)) {
		oputs(t.ploton);
		esc /= t.Hor;
		lead /= t.Vert;
		while (esc--)
			oputs(p);
		while (lead--)
			oputs(q);
		oputs(t.plotoff);
	}
	esc = lead = 0;

	return (0);
}


int
ptlead()
{
	move();

	return (0);
}


int
dostop()
{
	char	junk;

	flusho();
	read(2, &junk, 1);

	return (0);
}

int
newpage()
{
	return (0);
}


int
pttrailer()
{
	return (0);
}
