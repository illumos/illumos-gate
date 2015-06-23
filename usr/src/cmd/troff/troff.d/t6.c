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

/*
 * t6.c
 *
 * width functions, sizes and fonts
 */

#include "tdef.h"
#include "dev.h"
#include <ctype.h>
#include "ext.h"

/* fitab[f][c] is 0 if c is not on font f */
	/* if it's non-zero, c is in fontab[f] at position
	 * fitab[f][c].
	 */
extern	struct Font *fontbase[NFONT+1];
extern	char *codetab[NFONT+1];
extern int nchtab;

int	fontlab[NFONT+1];
short	*pstab;
int	cstab[NFONT+1];
int	ccstab[NFONT+1];
int	bdtab[NFONT+1];
int	sbold = 0;

int
width(j)
tchar j;
{
	int	i, k;

	if (j & (ZBIT|MOT)) {
		if (iszbit(j))
			return(0);
		if (isvmot(j))
			return(0);
		k = absmot(j);
		if (isnmot(j))
			k = -k;
		return(k);
	}
	i = cbits(j);
	if (i < ' ') {
		if (i == '\b')
			return(-widthp);
		if (i == PRESC)
			i = eschar;
		else if (iscontrol(i))
			return(0);
	}
	if (i==ohc)
		return(0);
	i = trtab[i];
	if (i < 32)
		return(0);
	if (sfbits(j) == oldbits) {
		xfont = pfont;
		xpts = ppts;
	} else
		xbits(j, 0);
	if (widcache[i-32].fontpts == (xfont<<8) + xpts && !setwdf)
		k = widcache[i-32].width;
	else {
		k = getcw(i-32);
		if (bd)
			k += (bd - 1) * HOR;
		if (cs)
			k = cs;
	}
	widthp = k;
	return(k);
}

/*
 * clear width cache-- s means just space
 */
int
zapwcache(s)
{
	int	i;

	if (s) {
		widcache[0].fontpts = 0;
		return (0);
	}
	for (i=0; i<NWIDCACHE; i++)
		widcache[i].fontpts = 0;

	return (0);
}

int
getcw(i)
int	i;
{
	int	k;
	char	*p;
	int	x, j;
	int nocache = 0;

	bd = 0;
	if (i >= nchtab + 128-32) {
		j = abscw(i + 32 - (nchtab+128));
		goto g0;
	}
	if (i == 0) {	/* a blank */
		k = (fontab[xfont][0] * spacesz + 6) / 12;
		/* this nonsense because .ss cmd uses 1/36 em as its units */
		/* and default is 12 */
		goto g1;
	}
	if ((j = fitab[xfont][i] & BYTEMASK) == 0) {	/* it's not on current font */
		/* search through search list of xfont
		 * to see what font it ought to be on.
		 * searches S, then remaining fonts in wraparound order.
		 */
		nocache = 1;
		if (smnt) {
			int ii, jj;
			for (ii=smnt, jj=0; jj < nfonts; jj++, ii=ii % nfonts + 1) {
				j = fitab[ii][i] & BYTEMASK;
				if (j != 0) {
					p = fontab[ii];
					k = *(p + j);
					if (xfont == sbold)
						bd = bdtab[ii];
					if (setwdf)
						numtab[CT].val |= kerntab[ii][j];
					goto g1;
				}
			}
		}
		k = fontab[xfont][0];	/* leave a space-size space */
		goto g1;
	}
 g0:
	p = fontab[xfont];
	if (setwdf)
		numtab[CT].val |= kerntab[xfont][j];
	k = *(p + j);
 g1:
	if (!bd)
		bd = bdtab[xfont];
	if (cs = cstab[xfont]) {
		nocache = 1;
		if (ccs = ccstab[xfont])
			x = ccs;
		else
			x = xpts;
		cs = (cs * EMPTS(x)) / 36;
	}
	k = ((k&BYTEMASK) * xpts + (Unitwidth / 2)) / Unitwidth;
	if (nocache|bd)
		widcache[i].fontpts = 0;
	else {
		widcache[i].fontpts = (xfont<<8) + xpts;
		widcache[i].width = k;
	}
	return(k);
	/* Unitwidth is Units/Point, where
	 * Units is the fundamental digitization
	 * of the character set widths, and
	 * Point is the number of goobies in a point
	 * e.g., for cat, Units=36, Point=6, so Unitwidth=36/6=6
	 * In effect, it's the size at which the widths
	 * translate directly into units.
	 */
}

int
abscw(n)	/* return index of abs char n in fontab[], etc. */
{	int i, ncf;

	ncf = fontbase[xfont]->nwfont & BYTEMASK;
	for (i = 0; i < ncf; i++)
		if (codetab[xfont][i] == n)
			return i;
	return 0;
}

int
xbits(i, bitf)
tchar i;
{
	int	k;

	xfont = fbits(i);
	k = sbits(i);
	if (k) {
		xpts = pstab[--k];
		oldbits = sfbits(i);
		pfont = xfont;
		ppts = xpts;
		return (0);
	}
	switch (bitf) {
	case 0:
		xfont = font;
		xpts = pts;
		break;
	case 1:
		xfont = pfont;
		xpts = ppts;
		break;
	case 2:
		xfont = mfont;
		xpts = mpts;
	}

	return (0);
}


tchar setch()
{
	int	j;
	char	temp[10];
	char	*s;
	extern char	*chname;
	extern short	*chtab;
	extern int	nchtab;

	s = temp;
	if ((*s++ = getach()) == 0 || (*s++ = getach()) == 0)
		return(0);
	*s = '\0';
	for (j = 0; j < nchtab; j++)
		if (strcmp(&chname[chtab[j]], temp) == 0)
			return(j + 128 | chbits);
	return(0);
}

tchar setabs()		/* set absolute char from \C'...' */
{
	int i, n, nf;
	extern int	nchtab;

	getch();
	n = 0;
	n = inumb(&n);
	getch();
	if (nonumb)
		return 0;
	return n + nchtab + 128;
}



int
findft(i)
int	i;
{
	int	k;

	if ((k = i - '0') >= 0 && k <= nfonts && k < smnt)
		return(k);
	for (k = 0; fontlab[k] != i; k++)
		if (k > nfonts)
			return(-1);
	return(k);
}


int
caseps()
{
	int	i;

	if (skip())
		i = apts1;
	else {
		noscale++;
		i = inumb(&apts);	/* this is a disaster for fractional point sizes */
		noscale = 0;
		if (nonumb)
			return (0);
	}
	casps1(i);

	return (0);
}


int
casps1(i)
int	i;
{

/*
 * in olden times, it used to ignore changes to 0 or negative.
 * this is meant to allow the requested size to be anything,
 * in particular so eqn can generate lots of \s-3's and still
 * get back by matching \s+3's.

	if (i <= 0)
		return (0);
*/
	apts1 = apts;
	apts = i;
	pts1 = pts;
	pts = findps(i);
	mchbits();

	return (0);
}


int
findps(i)
int	i;
{
	int	j, k;

	for (j=k=0 ; pstab[j] != 0 ; j++)
		if (abs(pstab[j]-i) < abs(pstab[k]-i))
			k = j;

	return(pstab[k]);
}


int
mchbits()
{
	int	i, j, k;

	i = pts;
	for (j = 0; i > (k = pstab[j]); j++)
		if (!k) {
			k = pstab[--j];
			break;
		}
	chbits = 0;
	setsbits(chbits, ++j);
	setfbits(chbits, font);
	sps = width(' ' | chbits);
	zapwcache(1);

	return (0);
}

int
setps()
{
	int i, j;

	i = cbits(getch());
	if (ischar(i) && isdigit(i)) {		/* \sd or \sdd */
		i -= '0';
		if (i == 0)		/* \s0 */
			j = apts1;
		else if (i <= 3 && ischar(j = cbits(ch = getch())) &&
		    isdigit(j)) {	/* \sdd */
			j = 10 * i + j - '0';
			ch = 0;
		} else		/* \sd */
			j = i;
	} else if (i == '(') {		/* \s(dd */
		j = cbits(getch()) - '0';
		j = 10 * j + cbits(getch()) - '0';
		if (j == 0)		/* \s(00 */
			j = apts1;
	} else if (i == '+' || i == '-') {	/* \s+, \s- */
		j = cbits(getch());
		if (ischar(j) && isdigit(j)) {		/* \s+d, \s-d */
			j -= '0';
		} else if (j == '(') {		/* \s+(dd, \s-(dd */
			j = cbits(getch()) - '0';
			j = 10 * j + cbits(getch()) - '0';
		}
		if (i == '-')
			j = -j;
		j += apts;
	}
	casps1(j);

	return (0);
}


tchar setht()		/* set character height from \H'...' */
{
	int n;
	tchar c;

	getch();
	n = inumb(&apts);
	getch();
	if (n == 0 || nonumb)
		n = apts;	/* does this work? */
	c = CHARHT;
	c |= ZBIT;
	setsbits(c, n);
	return(c);
}

tchar setslant()		/* set slant from \S'...' */
{
	int n;
	tchar c;

	getch();
	n = 0;
	n = inumb(&n);
	getch();
	if (nonumb)
		n = 0;
	c = SLANT;
	c |= ZBIT;
	setsfbits(c, n+180);
	return(c);
}


int
caseft()
{
	skip();
	setfont(1);

	return (0);
}


int
setfont(a)
int	a;
{
	int	i, j;

	if (a)
		i = getrq();
	else
		i = getsn();
	if (!i || i == 'P') {
		j = font1;
		goto s0;
	}
	if (i == 'S' || i == '0')
		return (0);
	if ((j = findft(i)) == -1)
		if ((j = setfp(0, i, 0)) == -1)	/* try to put it in position 0 */
			return (0);
s0:
	font1 = font;
	font = j;
	mchbits();

	return (0);
}


int
setwd()
{
	int	base, wid;
	tchar i;
	int	delim, emsz, k;
	int	savhp, savapts, savapts1, savfont, savfont1, savpts, savpts1;

	base = numtab[ST].val = wid = numtab[CT].val = 0;
	if (ismot(i = getch()))
		return (0);
	delim = cbits(i);
	savhp = numtab[HP].val;
	numtab[HP].val = 0;
	savapts = apts;
	savapts1 = apts1;
	savfont = font;
	savfont1 = font1;
	savpts = pts;
	savpts1 = pts1;
	setwdf++;
	while (cbits(i = getch()) != delim && !nlflg) {
		k = width(i);
		wid += k;
		numtab[HP].val += k;
		if (!ismot(i)) {
			emsz = POINT * xpts;
		} else if (isvmot(i)) {
			k = absmot(i);
			if (isnmot(i))
				k = -k;
			base -= k;
			emsz = 0;
		} else
			continue;
		if (base < numtab[SB].val)
			numtab[SB].val = base;
		if ((k = base + emsz) > numtab[ST].val)
			numtab[ST].val = k;
	}
	setn1(wid, 0, (tchar) 0);
	numtab[HP].val = savhp;
	apts = savapts;
	apts1 = savapts1;
	font = savfont;
	font1 = savfont1;
	pts = savpts;
	pts1 = savpts1;
	mchbits();
	setwdf = 0;

	return (0);
}


tchar vmot()
{
	dfact = lss;
	vflag++;
	return(mot());
}


tchar hmot()
{
	dfact = EM;
	return(mot());
}


tchar mot()
{
	int j, n;
	tchar i;

	j = HOR;
	getch(); /*eat delim*/
	if (n = atoi()) {
		if (vflag)
			j = VERT;
		i = makem(quant(n, j));
	} else
		i = 0;
	getch();
	vflag = 0;
	dfact = 1;
	return(i);
}


tchar sethl(k)
int	k;
{
	int	j;
	tchar i;

	j = EM / 2;
	if (k == 'u')
		j = -j;
	else if (k == 'r')
		j = -2 * j;
	vflag++;
	i = makem(j);
	vflag = 0;
	return(i);
}


tchar makem(i)
int	i;
{
	tchar j;

	if ((j = i) < 0)
		j = -j;
	j |= MOT;
	if (i < 0)
		j |= NMOT;
	if (vflag)
		j |= VMOT;
	return(j);
}


tchar getlg(i)
tchar i;
{
	tchar j, k;
	int lf;

	if ((lf = fontbase[fbits(i)]->ligfont) == 0) /* font lacks ligatures */
		return(i);
	j = getch0();
	if (cbits(j) == 'i' && (lf & LFI))
		j = LIG_FI;
	else if (cbits(j) == 'l' && (lf & LFL))
		j = LIG_FL;
	else if (cbits(j) == 'f' && (lf & LFF)) {
		if ((lf & (LFFI|LFFL)) && lg != 2) {
			k = getch0();
			if (cbits(k)=='i' && (lf&LFFI))
				j = LIG_FFI;
			else if (cbits(k)=='l' && (lf&LFFL))
				j = LIG_FFL;
			else {
				*pbp++ = k;
				j = LIG_FF;
			}
		} else
			j = LIG_FF;
	} else {
		*pbp++ = j;
		j = i;
	}
	return(i & SFMASK | j);
}


int
caselg()
{

	lg = 1;
	if (skip())
		return (0);
	lg = atoi();

	return (0);
}


int
casefp()
{
	int i, j;
	char *s;

	skip();
	if ((i = cbits(getch()) - '0') <= 0 || i > nfonts)
		errprint(gettext("fp: bad font position %d"), i);
	else if (skip() || !(j = getrq()))
		errprint(gettext("fp: no font name"));
	else if (skip() || !getname())
		setfp(i, j, 0);
	else		/* 3rd argument = filename */
		setfp(i, j, nextf);

	return (0);
}

int
setfp(pos, f, truename)	/* mount font f at position pos[0...nfonts] */
int pos, f;
char *truename;
{
	int	k;
	int n;
	char longname[NS], shortname[20];
	extern int nchtab;

	zapwcache(0);
	if (truename)
		strcpy(shortname, truename);
	else {
		shortname[0] = f & BYTEMASK;
		shortname[1] = f >> BYTE;
		shortname[2] = '\0';
	}
	sprintf(longname, "%s/dev%s/%s.out", fontfile, devname, shortname);
	if ((k = open(longname, 0)) < 0) {
		errprint(gettext("Can't open %s"), longname);
		return(-1);
	}
	n = fontbase[pos]->nwfont & BYTEMASK;
	read(k, (char *) fontbase[pos], 3*n + nchtab + 128 - 32 + sizeof(struct Font));
	kerntab[pos] = (char *) fontab[pos] + (fontbase[pos]->nwfont & BYTEMASK);
	/* have to reset the fitab pointer because the width may be different */
	fitab[pos] = (char *) fontab[pos] + 3 * (fontbase[pos]->nwfont & BYTEMASK);
	if ((fontbase[pos]->nwfont & BYTEMASK) > n) {
		errprint(gettext("Font %s too big for position %d"), shortname,
			pos);
		return(-1);
	}
	fontbase[pos]->nwfont = n;	/* so can load a larger one again later */
	close(k);
	if (pos == smnt) {
		smnt = 0;
		sbold = 0;
	}
	if ((fontlab[pos] = f) == 'S')
		smnt = pos;
	bdtab[pos] = cstab[pos] = ccstab[pos] = 0;
		/* if there is a directory, no place to store its name. */
		/* if position isn't zero, no place to store its value. */
		/* only time a FONTPOS is pushed back is if it's a */
		/* standard font on position 0 (i.e., mounted implicitly. */
		/* there's a bug here:  if there are several input lines */
		/* that look like .ft XX in short successtion, the output */
		/* will all be in the last one because the "x font ..." */
		/* comes out too soon.  pushing back FONTPOS doesn't work */
		/* with .ft commands because input is flushed after .xx cmds */
	ptfpcmd(pos, shortname);
	if (pos == 0)
		ch = (tchar) FONTPOS | (tchar) f << 16;
	return(pos);
}


int
casecs()
{
	int	i, j;

	noscale++;
	skip();
	if (!(i = getrq()) || (i = findft(i)) < 0)
		goto rtn;
	skip();
	cstab[i] = atoi();
	skip();
	j = atoi();
	if (nonumb)
		ccstab[i] = 0;
	else
		ccstab[i] = findps(j);
rtn:
	zapwcache(0);
	noscale = 0;

	return (0);
}


int
casebd()
{
	int	i, j, k;

	zapwcache(0);
	k = 0;
bd0:
	if (skip() || !(i = getrq()) || (j = findft(i)) == -1) {
		if (k)
			goto bd1;
		else
			return (0);
	}
	if (j == smnt) {
		k = smnt;
		goto bd0;
	}
	if (k) {
		sbold = j;
		j = k;
	}
bd1:
	skip();
	noscale++;
	bdtab[j] = atoi();
	noscale = 0;

	return (0);
}


int
casevs()
{
	int	i;

	skip();
	vflag++;
	dfact = INCH; /* default scaling is points! */
	dfactd = 72;
	res = VERT;
	i = inumb(&lss);
	if (nonumb)
		i = lss1;
	if (i < VERT)
		i = VERT;
	lss1 = lss;
	lss = i;

	return (0);
}


int
casess()
{
	int	i;

	noscale++;
	skip();
	if (i = atoi()) {
		spacesz = i & 0177;
		zapwcache(0);
		sps = width(' ' | chbits);
	}
	noscale = 0;

	return (0);
}


tchar xlss()
{
	/* stores \x'...' into
	 * two successive tchars.
	 * the first contains HX, the second the value,
	 * encoded as a vertical motion.
	 * decoding is done in n2.c by pchar().
	 */
	int	i;

	getch();
	dfact = lss;
	i = quant(atoi(), VERT);
	dfact = 1;
	getch();
	if (i >= 0)
		*pbp++ = MOT | VMOT | i;
	else
		*pbp++ = MOT | VMOT | NMOT | -i;
	return(HX);
}
