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
/*	  All Rights Reserved	*/

/*
 * University Copyright- Copyright (c) 1982, 1986, 1988
 * The Regents of the University of California
 * All Rights Reserved
 *
 * University Acknowledgment- Portions of this document are derived from
 * software developed by the University of California, Berkeley, and its
 * contributors.
 */

#ifdef EUC
#ifdef NROFF
#include <stdlib.h>
#include <widec.h>
#include <limits.h>
#endif /* NROFF */
#endif /* EUC */
#include "tdef.h"
#ifdef NROFF
#include "tw.h"
#endif
#ifdef NROFF
#define GETCH gettch
tchar	gettch();
#endif
#ifndef NROFF
#define GETCH getch
#endif

/*
 * troff7.c
 *
 * text
 */

#include <ctype.h>
#ifdef EUC
#ifdef NROFF
#include <wctype.h>
#endif /* NROFF */
#endif /* EUC */
#include "ext.h"
#ifdef EUC
#ifdef NROFF
char	mbbuf2[MB_LEN_MAX + 1];
char	*mbbuf2p = mbbuf2;
tchar	mtbuf[MB_LEN_MAX + 1];
tchar	*mtbufp;
int	pendmb = 0;
wchar_t	cwc, owc, wceoll;
#endif /* NROFF */
#endif /* EUC */
int	brflg;

int
tbreak()
{
	int	pad, k;
	tchar	*i, j;
	int resol = 0;
#ifdef EUC
#ifdef NROFF
	tchar	l;
#endif /* NROFF */
#endif /* EUC */

	trap = 0;
	if (nb)
		return (0);
	if (dip == d && numtab[NL].val == -1) {
		newline(1);
		return (0);
	}
	if (!nc) {
		setnel();
		if (!wch)
			return (0);
		if (pendw)
			getword(1);
		movword();
	} else if (pendw && !brflg) {
		getword(1);
		movword();
	}
	*linep = dip->nls = 0;
#ifdef NROFF
	if (dip == d)
		horiz(po);
#endif
	if (lnmod)
		donum();
	lastl = ne;
	if (brflg != 1) {
		totout = 0;
	} else if (ad) {
		if ((lastl = ll - un) < ne)
			lastl = ne;
	}
	if (admod && ad && (brflg != 2)) {
		lastl = ne;
		adsp = adrem = 0;
		if (admod == 1)
			un +=  quant(nel / 2, HOR);
		else if (admod == 2)
			un += nel;
	}
	totout++;
	brflg = 0;
	if (lastl + un > dip->maxl)
		dip->maxl = lastl + un;
	horiz(un);
#ifdef NROFF
	if (adrem % t.Adj)
		resol = t.Hor;
	else
		resol = t.Adj;
#else
	resol = HOR;
#endif
	adrem = (adrem / resol) * resol;
	for (i = line; nc > 0; ) {
#ifndef EUC
		if ((cbits(j = *i++)) == ' ') {
#else
#ifndef NROFF
		if ((cbits(j = *i++)) == ' ') {
#else
		if ((cbits(j = *i++) & ~MBMASK) == ' ') {
#endif /* NROFF */
#endif /* EUC */
			pad = 0;
			do {
				pad += width(j);
				nc--;
#ifndef EUC
			} while ((cbits(j = *i++)) == ' ');
#else
#ifndef NROFF
			} while ((cbits(j = *i++)) == ' ');
#else
			} while ((cbits(j = *i++) & ~MBMASK) == ' ');
#endif /* NROFF */
#endif /* EUC */
			i--;
			pad += adsp;
			--nwd;
			if (adrem) {
				if (adrem < 0) {
					pad -= resol;
					adrem += resol;
				} else if ((totout & 01) || adrem / resol >= nwd) {
					pad += resol;
					adrem -= resol;
				}
			}
			pchar((tchar) WORDSP);
			horiz(pad);
		} else {
			pchar(j);
			nc--;
		}
	}
	if (ic) {
		if ((k = ll - un - lastl + ics) > 0)
			horiz(k);
		pchar(ic);
	}
	if (icf)
		icf++;
	else
		ic = 0;
	ne = nwd = 0;
	un = in;
	setnel();
	newline(0);
	if (dip != d) {
		if (dip->dnl > dip->hnl)
			dip->hnl = dip->dnl;
	} else {
		if (numtab[NL].val > dip->hnl)
			dip->hnl = numtab[NL].val;
	}
	for (k = ls - 1; k > 0 && !trap; k--)
		newline(0);
	spread = 0;

	return (0);
}

int
donum()
{
	int	i, nw;
	extern int pchar();

	nrbits = nmbits;
	nw = width('1' | nrbits);
	if (nn) {
		nn--;
		goto d1;
	}
	if (numtab[LN].val % ndf) {
		numtab[LN].val++;
d1:
		un += nw * (3 + nms + ni);
		return (0);
	}
	i = 0;
	if (numtab[LN].val < 100)
		i++;
	if (numtab[LN].val < 10)
		i++;
	horiz(nw * (ni + i));
	nform = 0;
	fnumb(numtab[LN].val, pchar);
	un += nw * nms;
	numtab[LN].val++;

	return (0);
}

extern int logf;

int
text()
{
	tchar i;
	static int	spcnt;

	nflush++;
	numtab[HP].val = 0;
	if ((dip == d) && (numtab[NL].val == -1)) {
		newline(1);
		return (0);
	}
	setnel();
	if (ce || !fi) {
		nofill();
		return (0);
	}
	if (pendw)
		goto t4;
	if (pendt)
		if (spcnt)
			goto t2;
		else
			goto t3;
	pendt++;
	if (spcnt)
		goto t2;
	while ((cbits(i = GETCH())) == ' ') {
		spcnt++;
		numtab[HP].val += sps;
		widthp = sps;
	}
	if (nlflg) {
t1:
		nflush = pendt = ch = spcnt = 0;
		callsp();
		return (0);
	}
	ch = i;
	if (spcnt) {
t2:
		tbreak();
		if (nc || wch)
			goto rtn;
		un += spcnt * sps;
		spcnt = 0;
		setnel();
		if (trap)
			goto rtn;
		if (nlflg)
			goto t1;
	}
t3:
	if (spread)
		goto t5;
	if (pendw || !wch)
t4:
		if (getword(0))
			goto t6;
	if (!movword())
		goto t3;
t5:
	if (nlflg)
		pendt = 0;
	adsp = adrem = 0;
	if (ad) {
		if (nwd == 1)
			adsp = nel;
		else
			adsp = nel / (nwd - 1);
		adsp = (adsp / HOR) * HOR;
		adrem = nel - adsp*(nwd-1);
	}
	brflg = 1;
	tbreak();
	spread = 0;
	if (!trap)
		goto t3;
	if (!nlflg)
		goto rtn;
t6:
	pendt = 0;
	ckul();
rtn:
	nflush = 0;

	return (0);
}


int
nofill()
{
	int	j;
	tchar i;

	if (!pendnf) {
		over = 0;
		tbreak();
		if (trap)
			goto rtn;
		if (nlflg) {
			ch = nflush = 0;
			callsp();
			return (0);
		}
		adsp = adrem = 0;
		nwd = 10000;
	}
	while ((j = (cbits(i = GETCH()))) != '\n') {
		if (j == ohc)
			continue;
		if (j == CONT) {
			pendnf++;
			nflush = 0;
			flushi();
			ckul();
			return (0);
		}
		j = width(i);
		widthp = j;
		numtab[HP].val += j;
		storeline(i, j);
	}
	if (ce) {
		ce--;
		if ((i = quant(nel / 2, HOR)) > 0)
			un += i;
	}
	if (!nc)
		storeline((tchar)FILLER, 0);
	brflg = 2;
	tbreak();
	ckul();
rtn:
	pendnf = nflush = 0;

	return (0);
}


int
callsp()
{
	int	i;

	if (flss)
		i = flss;
	else
		i = lss;
	flss = 0;
	casesp(i);

	return (0);
}


int
ckul()
{
	if (ul && (--ul == 0)) {
		cu = 0;
		font = sfont;
		mchbits();
	}
	if (it && (--it == 0) && itmac)
		control(itmac, 0);

	return (0);
}


int
storeline(tchar c, int w)
{
	if (linep >= line + lnsize - 1) {
		if (!over) {
			flusho();
			errprint(gettext("Line overflow."));
			over++;
			c = LEFTHAND;
			w = -1;
			goto s1;
		}
		return (0);
	}
s1:
	if (w == -1)
		w = width(c);
	ne += w;
	nel -= w;
	*linep++ = c;
	nc++;

	return (0);
}


int
newline(a)
int	a;
{
	int	i, j, nlss;
	int	opn;

	if (a)
		goto nl1;
	if (dip != d) {
		j = lss;
		pchar1((tchar)FLSS);
		if (flss)
			lss = flss;
		i = lss + dip->blss;
		dip->dnl += i;
		pchar1((tchar)i);
		pchar1((tchar)'\n');
		lss = j;
		dip->blss = flss = 0;
		if (dip->alss) {
			pchar1((tchar)FLSS);
			pchar1((tchar)dip->alss);
			pchar1((tchar)'\n');
			dip->dnl += dip->alss;
			dip->alss = 0;
		}
		if (dip->ditrap && !dip->ditf && dip->dnl >= dip->ditrap && dip->dimac)
			if (control(dip->dimac, 0)) {
				trap++;
				dip->ditf++;
			}
		return (0);
	}
	j = lss;
	if (flss)
		lss = flss;
	nlss = dip->alss + dip->blss + lss;
	numtab[NL].val += nlss;
#ifndef NROFF
	if (ascii) {
		dip->alss = dip->blss = 0;
	}
#endif
	pchar1((tchar)'\n');
	flss = 0;
	lss = j;
	if (numtab[NL].val < pl)
		goto nl2;
nl1:
	ejf = dip->hnl = numtab[NL].val = 0;
	ejl = frame;
	if (donef) {
		if ((!nc && !wch) || ndone)
			done1(0);
		ndone++;
		donef = 0;
		if (frame == stk)
			nflush++;
	}
	opn = numtab[PN].val;
	numtab[PN].val++;
	if (npnflg) {
		numtab[PN].val = npn;
		npn = npnflg = 0;
	}
nlpn:
	if (numtab[PN].val == pfrom) {
		print++;
		pfrom = -1;
	} else if (opn == pto) {
		print = 0;
		opn = -1;
		chkpn();
		goto nlpn;
	}
	if (print)
		newpage(numtab[PN].val);	/* supposedly in a clean state so can pause */
	if (stop && print) {
		dpn++;
		if (dpn >= stop) {
			dpn = 0;
			dostop();
		}
	}
nl2:
	trap = 0;
	if (numtab[NL].val == 0) {
		if ((j = findn(0)) != NTRAP)
			trap = control(mlist[j], 0);
	} else if ((i = findt(numtab[NL].val - nlss)) <= nlss) {
		if ((j = findn1(numtab[NL].val - nlss + i)) == NTRAP) {
			flusho();
			errprint(gettext("Trap botch."));
			done2(-5);
		}
		trap = control(mlist[j], 0);
	}

	return (0);
}


int
findn1(a)
int	a;
{
	int	i, j;

	for (i = 0; i < NTRAP; i++) {
		if (mlist[i]) {
			if ((j = nlist[i]) < 0)
				j += pl;
			if (j == a)
				break;
		}
	}
	return(i);
}

int
chkpn()
{
	pto = *(pnp++);
	pfrom = pto>=0 ? pto : -pto;
	if (pto == -32767) {
		flusho();
		done1(0);
	}
	if (pto < 0) {
		pto = -pto;
		print++;
		pfrom = 0;
	}

	return (0);
}


int
findt(a)
int	a;
{
	int	i, j, k;

	k = 32767;
	if (dip != d) {
		if (dip->dimac && (i = dip->ditrap - a) > 0)
			k = i;
		return(k);
	}
	for (i = 0; i < NTRAP; i++) {
		if (mlist[i]) {
			if ((j = nlist[i]) < 0)
				j += pl;
			if ((j -= a) <= 0)
				continue;
			if (j < k)
				k = j;
		}
	}
	i = pl - a;
	if (k > i)
		k = i;
	return(k);
}


int
findt1()
{
	int	i;

	if (dip != d)
		i = dip->dnl;
	else
		i = numtab[NL].val;
	return(findt(i));
}


int
eject(a)
struct s *a;
{
	int	savlss;

	if (dip != d)
		return (0);
	ejf++;
	if (a)
		ejl = a;
	else
		ejl = frame;
	if (trap)
		return (0);
e1:
	savlss = lss;
	lss = findt(numtab[NL].val);
	newline(0);
	lss = savlss;
	if (numtab[NL].val && !trap)
		goto e1;

	return (0);
}


int
movword()
{
	int	w;
	tchar i, *wp;
	int	savwch, hys;

	over = 0;
	wp = wordp;
	if (!nwd) {
#ifndef EUC
		while (cbits(i = *wp++) == ' ') {
#else
#ifndef NROFF
		while (cbits(i = *wp++) == ' ') {
#else
		while ((cbits(i = *wp++) & ~MBMASK) == ' ') {
#endif /* NROFF */
#endif /* EUC */
			wch--;
			wne -= sps;
		}
		wp--;
	}
	if (wne > nel && !hyoff && hyf && (!nwd || nel > 3 * sps) &&
	   (!(hyf & 02) || (findt1() > lss)))
		hyphen(wp);
	savwch = wch;
	hyp = hyptr;
	nhyp = 0;
	while (*hyp && *hyp <= wp)
		hyp++;
	while (wch) {
		if (hyoff != 1 && *hyp == wp) {
			hyp++;
			if (!wdstart || (wp > wdstart + 1 && wp < wdend &&
			   (!(hyf & 04) || wp < wdend - 1) &&		/* 04 => last 2 */
			   (!(hyf & 010) || wp > wdstart + 2))) {	/* 010 => 1st 2 */
				nhyp++;
				storeline((tchar)IMP, 0);
			}
		}
		i = *wp++;
		w = width(i);
		wne -= w;
		wch--;
		storeline(i, w);
	}
	if (nel >= 0) {
		nwd++;
		return(0);	/* line didn't fill up */
	}
#ifndef NROFF
	xbits((tchar)HYPHEN, 1);
#endif
	hys = width((tchar)HYPHEN);
m1:
	if (!nhyp) {
		if (!nwd)
			goto m3;
		if (wch == savwch)
			goto m4;
	}
	if (*--linep != IMP)
		goto m5;
	if (!(--nhyp))
		if (!nwd)
			goto m2;
	if (nel < hys) {
		nc--;
		goto m1;
	}
m2:
	if ((i = cbits(*(linep - 1))) != '-' && i != EMDASH) {
		*linep = (*(linep - 1) & SFMASK) | HYPHEN;
		w = width(*linep);
		nel -= w;
		ne += w;
		linep++;
	}
m3:
	nwd++;
m4:
	wordp = wp;
	return(1);	/* line filled up */
m5:
	nc--;
	w = width(*linep);
	ne -= w;
	nel += w;
	wne += w;
	wch++;
	wp--;
	goto m1;
}


int
horiz(i)
int	i;
{
	vflag = 0;
	if (i)
		pchar(makem(i));

	return (0);
}


int
setnel()
{
	if (!nc) {
		linep = line;
		if (un1 >= 0) {
			un = un1;
			un1 = -1;
		}
		nel = ll - un;
		ne = adsp = adrem = 0;
	}

	return (0);
}

int
getword(x)
int	x;
{
	int j, k;
	tchar i, *wp;
	int noword;
#ifdef EUC
#ifdef NROFF
	wchar_t *wddelim;
	char mbbuf3[MB_LEN_MAX + 1];
	char *mbbuf3p;
	int wbf, n;
	tchar m;
#endif /* NROFF */
#endif /* EUC */

	noword = 0;
	if (x)
		if (pendw) {
			*pendw = 0;
			goto rtn;
		}
	if (wordp = pendw)
		goto g1;
	hyp = hyptr;
	wordp = word;
	over = wne = wch = 0;
	hyoff = 0;
#ifdef EUC
#ifdef NROFF
	mtbufp = mtbuf;
	if (pendmb) {
		while(*mtbufp) {
			switch(*mtbufp & MBMASK) {
			case LASTOFMB:
			case BYTE_CHR:
				storeword(*mtbufp++, -1);
				break;

			default:
				storeword(*mtbufp++, 0);
			}
		}
		mtbufp = mtbuf;
		pendmb = 0;
		goto g1;
	}
#endif /* NROFF */
#endif /* EUC */
	while (1) {	/* picks up 1st char of word */
		j = cbits(i = GETCH());
#ifdef EUC
#ifdef NROFF
		if (multi_locale)
			if (collectmb(i))
				continue;
#endif /* NROFF */
#endif /* EUC */
		if (j == '\n') {
			wne = wch = 0;
			noword = 1;
			goto rtn;
		}
		if (j == ohc) {
			hyoff = 1;	/* 1 => don't hyphenate */
			continue;
		}
		if (j == ' ') {
			numtab[HP].val += sps;
			widthp = sps;
			storeword(i, sps);
			continue;
		}
		break;
	}
#ifdef EUC
#ifdef NROFF
	if (!multi_locale)
		goto a0;
	if (wddlm && iswprint(wceoll) && iswprint(cwc) &&
	    (!iswascii(wceoll) || !iswascii(cwc)) &&
	    !iswspace(wceoll) && !iswspace(cwc)) {
		wddelim = (*wddlm)(wceoll, cwc, 1);
		wceoll = 0;
		if (*wddelim != ' ') {
			if (!*wddelim) {
				storeword(((*wdbdg)(wceoll, cwc, 1) < 3) ?
					  ZWDELIM(1) : ZWDELIM(2), 0);
			} else {
				while (*wddelim) {
					if ((n = wctomb(mbbuf3, *wddelim++))
					    > 0) {
						mbbuf3[n] = 0;
						n--;
						mbbuf3p = mbbuf3 + n;
						while(n) {
							m = *(mbbuf3p-- - n--) &
							    0xff | MIDDLEOFMB |
							    ZBIT;
							storeword(m, 0);
						}
						m = *mbbuf3p & 0xff | LASTOFMB;
						storeword(m, -1);
					} else {
						storeword(' ' | chbits, sps);
						break;
					}
				}
			}
			spflg = 0;
			goto g0;
		}
	}
a0:
#endif /* NROFF */
#endif /* EUC */
	storeword(' ' | chbits, sps);
	if (spflg) {
		storeword(' ' | chbits, sps);
		spflg = 0;
	}
g0:
	if (j == CONT) {
		pendw = wordp;
		nflush = 0;
		flushi();
		return(1);
	}
	if (hyoff != 1) {
		if (j == ohc) {
			hyoff = 2;
			*hyp++ = wordp;
			if (hyp > (hyptr + NHYP - 1))
				hyp = hyptr + NHYP - 1;
			goto g1;
		}
		if (j == '-' || j == EMDASH)
			if (wordp > word + 1) {
				hyoff = 2;
				*hyp++ = wordp + 1;
				if (hyp > (hyptr + NHYP - 1))
					hyp = hyptr + NHYP - 1;
			}
	}
	j = width(i);
	numtab[HP].val += j;
#ifndef EUC
	storeword(i, j);
#else
#ifndef NROFF
	storeword(i, j);
#else
	if (multi_locale) {
		mtbufp = mtbuf;
		while(*mtbufp) {
			switch(*mtbufp & MBMASK) {
			case LASTOFMB:
			case BYTE_CHR:
				storeword(*mtbufp++, j);
				break;

			default:
				storeword(*mtbufp++, 0);
			}
		}
		mtbufp = mtbuf;
	} else {
		storeword(i, j);
	}
#endif /* NROFF */
#endif /* EUC */
g1:
	j = cbits(i = GETCH());
#ifdef EUC
#ifdef NROFF
	if (multi_locale)
		if (collectmb(i))
			goto g1;
#endif /* NROFF */
#endif /* EUC */
	if (j != ' ') {
		static char *sentchar = ".?!:";	/* sentence terminators */
		if (j != '\n')
#ifdef EUC
#ifdef NROFF
			if (!multi_locale)
#endif /* NROFF */
#endif /* EUC */
			goto g0;
#ifdef EUC
#ifdef NROFF
			else {
				if (!wdbdg || (iswascii(cwc) && iswascii(owc)))
					goto g0;
				if ((wbf = (*wdbdg)(owc, cwc, 1)) < 5) {
					pendmb++;
					storeword((wbf < 3) ? ZWDELIM(1) :
						  ZWDELIM(2), 0);
					*wordp = 0;
					goto rtn;
				} else goto g0;
			}
#endif /* NROFF */
#endif /* EUC */
		wp = wordp-1;	/* handle extra space at end of sentence */
		while (wp >= word) {
			j = cbits(*wp--);
			if (j=='"' || j=='\'' || j==')' || j==']' || j=='*' || j==DAGGER)
				continue;
			for (k = 0; sentchar[k]; k++)
				if (j == sentchar[k]) {
					spflg++;
					break;
				}
			break;
		}
	}
#ifdef EUC
#ifdef NROFF
	wceoll = owc;
#endif /* NROFF */
#endif /* EUC */
	*wordp = 0;
	numtab[HP].val += sps;
rtn:
	for (wp = word; *wp; wp++) {
		j = cbits(*wp);
		if (j == ' ')
			continue;
		if (!ischar(j) || (!isdigit(j) && j != '-'))
			break;
	}
	if (*wp == 0)	/* all numbers, so don't hyphenate */
		hyoff = 1;
	wdstart = 0;
	wordp = word;
	pendw = 0;
	*hyp++ = 0;
	setnel();
	return(noword);
}


int
storeword(c, w)
tchar c;
int	w;
{

	if (wordp >= &word[WDSIZE - 3]) {
		if (!over) {
			flusho();
			errprint(gettext("Word overflow."));
			over++;
			c = LEFTHAND;
			w = -1;
			goto s1;
		}
		return (0);
	}
s1:
	if (w == -1)
		w = width(c);
	widthp = w;
	wne += w;
	*wordp++ = c;
	wch++;

	return (0);
}


#ifdef NROFF
tchar gettch()
{
	extern int c_isalnum;
	tchar i;
	int j;

	i = getch();
	j = cbits(i);
	if (ismot(i) || fbits(i) != ulfont)
		return(i);
	if (cu) {
		if (trtab[j] == ' ') {
			setcbits(i, '_');
			setfbits(i, FT);	/* default */
		}
		return(i);
	}
	/* should test here for characters that ought to be underlined */
	/* in the old nroff, that was the 200 bit on the width! */
	/* for now, just do letters, digits and certain special chars */
	if (j <= 127) {
		if (!isalnum(j))
			setfbits(i, FT);
	} else {
		if (j < c_isalnum)
			setfbits(i, FT);
	}
	return(i);
}


#endif
#ifdef EUC
#ifdef NROFF
int
collectmb(i)
tchar	i;
{
	int busy;

	*mtbufp++ = i;
	*mbbuf2p++ = i & BYTEMASK;
	*mtbufp = *mbbuf2p = 0;
	if (ismot(i)) {
		mtbufp = mtbuf;
		mbbuf2p = mbbuf2;
		owc = 0;
		cwc = 0;
		return(busy = 0);
	}
	if ((i & MBMASK) == MIDDLEOFMB) {
		if (mtbufp <= (mtbuf + MB_CUR_MAX)) {
			busy = 1;
		} else {
			*(mtbufp - 1) &= ~MBMASK;
			goto gotmb;
		}
	} else {
		if ((i & MBMASK) == LASTOFMB)
			*(mtbufp - 1) &= ~MBMASK;
gotmb:
		mtbufp = mtbuf;
		owc = cwc;
		if (mbtowc(&cwc, mbbuf2, MB_CUR_MAX) <= 0) {
			mtbufp = mtbuf;
			while (*mtbufp) {
				setcbits(*mtbufp, (*mtbufp & 0x1ff));
				mtbufp++;
			}
			mtbufp = mtbuf;
		}
		mbbuf2p = mbbuf2;
		busy = 0;
	}
	return(busy);
}


#endif /* NROFF */
#endif /* EUC */
