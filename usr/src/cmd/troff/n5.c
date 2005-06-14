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


#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * University Copyright- Copyright (c) 1982, 1986, 1988
 * The Regents of the University of California
 * All Rights Reserved
 *
 * University Acknowledgment- Portions of this document are derived from
 * software developed by the University of California, Berkeley, and its
 * contributors.
 */

#ifdef 	EUC
#ifdef	NROFF
#include <stddef.h>
#include <stdlib.h>
#include <widec.h>
#endif	/* NROFF */
#endif	/* EUC */
#include <string.h>
#include "tdef.h"
#include "ext.h"

/*
 * troff5.c
 * 
 * misc processing requests
 */

int	iflist[NIF];
int	ifx;

casead()
{
	register i;

	ad = 1;
	/*leave admod alone*/
	if (skip())
		return;
	switch (i = cbits(getch())) {
	case 'r':	/*right adj, left ragged*/
		admod = 2;
		break;
	case 'l':	/*left adj, right ragged*/
		admod = ad = 0;	/*same as casena*/
		break;
	case 'c':	/*centered adj*/
		admod = 1;
		break;
	case 'b': 
	case 'n':
		admod = 0;
		break;
	case '0': 
	case '2': 
	case '4':
		ad = 0;
	case '1': 
	case '3': 
	case '5':
		admod = (i - '0') / 2;
	}
}


casena()
{
	ad = 0;
}


casefi()
{
	tbreak();
	fi++;
	pendnf = 0;
	lnsize = LNSIZE;
}


casenf()
{
	tbreak();
	fi = 0;
}


casers()
{
	dip->nls = 0;
}


casens()
{
	dip->nls++;
}


chget(c)
int	c;
{
	tchar i;

	if (skip() || ismot(i = getch()) || cbits(i) == ' ' || cbits(i) == '\n') {
		ch = i;
		return(c);
	} else 
		return(i & BYTEMASK);
}


casecc()
{
	cc = chget('.');
}


casec2()
{
	c2 = chget('\'');
}


casehc()
{
	ohc = chget(OHC);
}


casetc()
{
	tabc = chget(0);
}


caselc()
{
	dotc = chget(0);
}


casehy()
{
	register i;

	hyf = 1;
	if (skip())
		return;
	noscale++;
	i = atoi();
	noscale = 0;
	if (nonumb)
		return;
	hyf = max(i, 0);
}


casenh()
{
	hyf = 0;
}


max(aa, bb)
int	aa, bb;
{
	if (aa > bb)
		return(aa);
	else 
		return(bb);
}


casece()
{
	register i;

	noscale++;
	skip();
	i = max(atoi(), 0);
	if (nonumb)
		i = 1;
	tbreak();
	ce = i;
	noscale = 0;
}


casein()
{
	register i;

	if (skip())
		i = in1;
	else 
		i = max(hnumb(&in), 0);
	tbreak();
	in1 = in;
	in = i;
	if (!nc) {
		un = in;
		setnel();
	}
}


casell()
{
	register i;

	if (skip())
		i = ll1;
	else 
		i = max(hnumb(&ll), INCH / 10);
	ll1 = ll;
	ll = i;
	setnel();
}


caselt()
{
	register i;

	if (skip())
		i = lt1;
	else 
		i = max(hnumb(&lt), 0);
	lt1 = lt;
	lt = i;
}


caseti()
{
	register i;

	if (skip())
		return;
	i = max(hnumb(&in), 0);
	tbreak();
	un1 = i;
	setnel();
}


casels()
{
	register i;

	noscale++;
	if (skip())
		i = ls1;
	else 
		i = max(inumb(&ls), 1);
	ls1 = ls;
	ls = i;
	noscale = 0;
}


casepo()
{
	register i;

	if (skip())
		i = po1;
	else 
		i = max(hnumb(&po), 0);
	po1 = po;
	po = i;
#ifndef NROFF
	if (!ascii)
		esc += po - po1;
#endif
}


casepl()
{
	register i;

	skip();
	if ((i = vnumb(&pl)) == 0)
		pl = 11 * INCH; /*11in*/
	else 
		pl = i;
	if (numtab[NL].val > pl)
		numtab[NL].val = pl;
}


casewh()
{
	register i, j, k;

	lgf++;
	skip();
	i = vnumb((int *)0);
	if (nonumb)
		return;
	skip();
	j = getrq();
	if ((k = findn(i)) != NTRAP) {
		mlist[k] = j;
		return;
	}
	for (k = 0; k < NTRAP; k++)
		if (mlist[k] == 0)
			break;
	if (k == NTRAP) {
		flusho();
		errprint(gettext("cannot plant trap."));
		return;
	}
	mlist[k] = j;
	nlist[k] = i;
}


casech()
{
	register i, j, k;

	lgf++;
	skip();
	if (!(j = getrq()))
		return;
	else 
		for (k = 0; k < NTRAP; k++)
			if (mlist[k] == j)
				break;
	if (k == NTRAP)
		return;
	skip();
	i = vnumb((int *)0);
	if (nonumb)
		mlist[k] = 0;
	nlist[k] = i;
}


findn(i)
int	i;
{
	register k;

	for (k = 0; k < NTRAP; k++)
		if ((nlist[k] == i) && (mlist[k] != 0))
			break;
	return(k);
}


casepn()
{
	register i;

	skip();
	noscale++;
	i = max(inumb(&numtab[PN].val), 0);
	noscale = 0;
	if (!nonumb) {
		npn = i;
		npnflg++;
	}
}


casebp()
{
	register i;
	register struct s *savframe;

	if (dip != d)
		return;
	savframe = frame;
	skip();
	if ((i = inumb(&numtab[PN].val)) < 0)
		i = 0;
	tbreak();
	if (!nonumb) {
		npn = i;
		npnflg++;
	} else if (dip->nls)
		return;
	eject(savframe);
}


casetm(ab) 
	int ab;
{
	register i;
	char	tmbuf[NTM];

	lgf++;
	copyf++;
	if (skip() && ab)
		errprint(gettext("User Abort"));
	for (i = 0; i < NTM - 2; )
		if ((tmbuf[i++] = getch()) == '\n')
			break;
	if (i == NTM - 2)
		tmbuf[i++] = '\n';
	tmbuf[i] = 0;
	if (ab)	/* truncate output */
		obufp = obuf;	/* should be a function in n2.c */
	flusho();
	fdprintf(stderr, "%s", tmbuf);
	copyf--;
	lgf--;
}


casesp(a)
int	a;
{
	register i, j, savlss;

	tbreak();
	if (dip->nls || trap)
		return;
	i = findt1();
	if (!a) {
		skip();
		j = vnumb((int *)0);
		if (nonumb)
			j = lss;
	} else 
		j = a;
	if (j == 0)
		return;
	if (i < j)
		j = i;
	savlss = lss;
	if (dip != d)
		i = dip->dnl; 
	else 
		i = numtab[NL].val;
	if ((i + j) < 0)
		j = -i;
	lss = j;
	newline(0);
	lss = savlss;
}


casert()
{
	register a, *p;

	skip();
	if (dip != d)
		p = &dip->dnl; 
	else 
		p = &numtab[NL].val;
	a = vnumb(p);
	if (nonumb)
		a = dip->mkline;
	if ((a < 0) || (a >= *p))
		return;
	nb++;
	casesp(a - *p);
}


caseem()
{
	lgf++;
	skip();
	em = getrq();
}


casefl()
{
	tbreak();
	flusho();
}


caseev()
{
	register nxev;

	if (skip()) {
e0:
		if (evi == 0)
			return;
		nxev =  evlist[--evi];
		goto e1;
	}
	noscale++;
	nxev = atoi();
	noscale = 0;
	if (nonumb)
		goto e0;
	flushi();
	if ((nxev >= NEV) || (nxev < 0) || (evi >= EVLSZ)) {
		flusho();
		errprint(gettext("cannot do ev."));
		if (error)
			done2(040);
		else 
			edone(040);
		return;
	}
	evlist[evi++] = ev;
e1:
	if (ev == nxev)
		return;
#ifdef INCORE
	{
		extern tchar corebuf[];
		*(struct env *)&corebuf[ev * sizeof(env)/sizeof(tchar)] = env;
		env = *(struct env *)&corebuf[nxev * sizeof(env)/sizeof(tchar)];
	}
#else
	lseek(ibf, ev * (long)sizeof(env), 0);
	write(ibf, (char *) & env, sizeof(env));
	lseek(ibf, nxev * (long)sizeof(env), 0);
	read(ibf, (char *) & env, sizeof(env));
#endif
	ev = nxev;
}

caseel()
{
	if (--ifx < 0) {
		ifx = 0;
		iflist[0] = 0;
	}
	caseif(2);
}


caseie()
{
	if (ifx >= NIF) {
		errprint(gettext("if-else overflow."));
		ifx = 0;
		edone(040);
	}
	caseif(1);
	ifx++;
}


caseif(x)
int	x;
{
	extern int falsef;
	register notflag, true;
	tchar i;

	if (x == 2) {
		notflag = 0;
		true = iflist[ifx];
		goto i1;
	}
	true = 0;
	skip();
	if ((cbits(i = getch())) == '!') {
		notflag = 1;
	} else {
		notflag = 0;
		ch = i;
	}
	i = atoi();
	if (!nonumb) {
		if (i > 0)
			true++;
		goto i1;
	}
	i = getch();
	switch (cbits(i)) {
	case 'e':
		if (!(numtab[PN].val & 01))
			true++;
		break;
	case 'o':
		if (numtab[PN].val & 01)
			true++;
		break;
#ifdef NROFF
	case 'n':
		true++;
	case 't':
#endif
#ifndef NROFF
	case 't':
		true++;
	case 'n':
#endif
	case ' ':
		break;
	default:
		true = cmpstr(i);
	}
i1:
	true ^= notflag;
	if (x == 1)
		iflist[ifx] = !true;
	if (true) {
i2:
		while ((cbits(i = getch())) == ' ')
			;
		if (cbits(i) == LEFT)
			goto i2;
		ch = i;
		nflush++;
	} else {
		copyf++;
		falsef++;
		eatblk(0);
		copyf--;
		falsef--;
	}
}

eatblk(inblk)
int inblk;
{	register int cnt, i;

	cnt = 0;
	do {
		if (ch)	{
			i = cbits(ch);
			ch = 0;
		} else
			i = cbits(getch0());
		if (i == ESC)
			cnt++;
		else {
			if (cnt == 1)
				switch (i) {
				case '{':  i = LEFT; break;
				case '}':  i = RIGHT; break;
				case '\n': i = 'x'; break;
				}
			cnt = 0;
		}
		if (i == LEFT) eatblk(1);
	} while ((!inblk && (i != '\n')) || (inblk && (i != RIGHT)));
	if (i == '\n')
		nlflg++;
}


cmpstr(c)
tchar c;
{
	register j, delim;
	register tchar i;
	register val;
	int savapts, savapts1, savfont, savfont1, savpts, savpts1;
	tchar string[1280];
	register tchar *sp;

	if (ismot(c))
		return(0);
	delim = cbits(c);
	savapts = apts;
	savapts1 = apts1;
	savfont = font;
	savfont1 = font1;
	savpts = pts;
	savpts1 = pts1;
	sp = string;
	while ((j = cbits(i = getch()))!=delim && j!='\n' && sp<&string[1280-1])
		*sp++ = i;
	if (sp >= string + 1280) {
		errprint(gettext("too-long string compare."));
		edone(0100);
	}
	if (nlflg) {
		val = sp==string;
		goto rtn;
	}
	*sp++ = 0;
	apts = savapts;
	apts1 = savapts1;
	font = savfont;
	font1 = savfont1;
	pts = savpts;
	pts1 = savpts1;
	mchbits();
	val = 1;
	sp = string;
	while ((j = cbits(i = getch())) != delim && j != '\n') {
		if (*sp != i) {
			eat(delim);
			val = 0;
			goto rtn;
		}
		sp++;
	}
	if (*sp)
		val = 0;
rtn:
	apts = savapts;
	apts1 = savapts1;
	font = savfont;
	font1 = savfont1;
	pts = savpts;
	pts1 = savpts1;
	mchbits();
	return(val);
}


caserd()
{

	lgf++;
	skip();
	getname();
	if (!iflg) {
		if (quiet) {
#ifdef	NROFF
			echo_off();
			flusho();
#endif	NROFF
			fdprintf(stderr, "\007"); /*bell*/
		} else {
			if (nextf[0]) {
				fdprintf(stderr, "%s:", nextf);
			} else {
				fdprintf(stderr, "\007"); /*bell*/
			}
		}
	}
	collect();
	tty++;
	pushi(NBLIST*BLK, PAIR('r','d'));
}


rdtty()
{
	char	onechar;
#ifdef EUC
#ifdef NROFF
	int	i, n, col_index;
#endif /* NROFF */
#endif /* EUC */

	onechar = 0;
	if (read(0, &onechar, 1) == 1) {
		if (onechar == '\n')
			tty++;
		else 
			tty = 1;
#ifndef EUC
		if (tty != 3)
			return(onechar);
#else
#ifndef NROFF
		if (tty != 3)
			return(onechar);
#else
		if (tty != 3) {
			if (!multi_locale)
				return(onechar);
			i = onechar & 0377;
			*mbbuf1p++ = i;
			*mbbuf1p = 0;
			if ((n = mbtowc(&twc, mbbuf1, MB_CUR_MAX)) <= 0) {
				if (mbbuf1p >= mbbuf1 + MB_CUR_MAX) {
					i &= ~(MBMASK | CSMASK);
					twc = 0;
					mbbuf1p = mbbuf1;
					*mbbuf1p = 0;
				} else {
					i |= (MIDDLEOFMB);
				}
			} else {
				if (n > 1)
					i |= (LASTOFMB);
				else
					i |= (BYTE_CHR);
				if (isascii(twc)) {
					col_index = 0;
				} else {
					if ((col_index = wcwidth(twc)) < 0)
						col_index = 0;
				}
				setcsbits(i, col_index);
				twc = 0;
				mbbuf1p = mbbuf1;
			}
			return(i);
		}
#endif /* NROFF */
#endif /* EUC */
	}
	popi();
	tty = 0;
#ifdef	NROFF
	if (quiet)
		echo_on();
#endif	NROFF
	return(0);
}


caseec()
{
	eschar = chget('\\');
}


caseeo()
{
	eschar = 0;
}


caseta()
{
	register i;

	tabtab[0] = nonumb = 0;
	for (i = 0; ((i < (NTAB - 1)) && !nonumb); i++) {
		if (skip())
			break;
		tabtab[i] = max(hnumb(&tabtab[max(i-1,0)]), 0) & TABMASK;
		if (!nonumb) 
			switch (cbits(ch)) {
			case 'C':
				tabtab[i] |= CTAB;
				break;
			case 'R':
				tabtab[i] |= RTAB;
				break;
			default: /*includes L*/
				break;
			}
		nonumb = ch = 0;
	}
	tabtab[i] = 0;
}


casene()
{
	register i, j;

	skip();
	i = vnumb((int *)0);
	if (nonumb)
		i = lss;
	if (i > (j = findt1())) {
		i = lss;
		lss = j;
		dip->nls = 0;
		newline(0);
		lss = i;
	}
}


casetr()
{
	register i, j;
	tchar k;

	lgf++;
	skip();
	while ((i = cbits(k=getch())) != '\n') {
		if (ismot(k))
			return;
		if (ismot(k = getch()))
			return;
		if ((j = cbits(k)) == '\n')
			j = ' ';
		trtab[i] = j;
	}
}


casecu()
{
	cu++;
	caseul();
}


caseul()
{
	register i;

	noscale++;
	if (skip())
		i = 1;
	else 
		i = atoi();
	if (ul && (i == 0)) {
		font = sfont;
		ul = cu = 0;
	}
	if (i) {
		if (!ul) {
			sfont = font;
			font = ulfont;
		}
		ul = i;
	}
	noscale = 0;
	mchbits();
}


caseuf()
{
	register i, j;

	if (skip() || !(i = getrq()) || i == 'S' ||  (j = findft(i))  == -1)
		ulfont = ULFONT; /*default underline position*/
	else 
		ulfont = j;
#ifdef NROFF
	if (ulfont == FT)
		ulfont = ULFONT;
#endif
}


caseit()
{
	register i;

	lgf++;
	it = itmac = 0;
	noscale++;
	skip();
	i = atoi();
	skip();
	if (!nonumb && (itmac = getrq()))
		it = i;
	noscale = 0;
}


casemc()
{
	register i;

	if (icf > 1)
		ic = 0;
	icf = 0;
	if (skip())
		return;
	ic = getch();
	icf = 1;
	skip();
	i = max(hnumb((int *)0), 0);
	if (!nonumb)
		ics = i;
}


casemk()
{
	register i, j;

	if (dip != d)
		j = dip->dnl; 
	else 
		j = numtab[NL].val;
	if (skip()) {
		dip->mkline = j;
		return;
	}
	if ((i = getrq()) == 0)
		return;
	numtab[findr(i)].val = j;
}


casesv()
{
	register i;

	skip();
	if ((i = vnumb((int *)0)) < 0)
		return;
	if (nonumb)
		i = 1;
	sv += i;
	caseos();
}


caseos()
{
	register savlss;

	if (sv <= findt1()) {
		savlss = lss;
		lss = sv;
		newline(0);
		lss = savlss;
		sv = 0;
	}
}


casenm()
{
	register i;

	lnmod = nn = 0;
	if (skip())
		return;
	lnmod++;
	noscale++;
	i = inumb(&numtab[LN].val);
	if (!nonumb)
		numtab[LN].val = max(i, 0);
	getnm(&ndf, 1);
	getnm(&nms, 0);
	getnm(&ni, 0);
	noscale = 0;
	nmbits = chbits;
}


getnm(p, min)
int	*p, min;
{
	register i;

	eat(' ');
	if (skip())
		return;
	i = atoi();
	if (nonumb)
		return;
	*p = max(i, min);
}


casenn()
{
	noscale++;
	skip();
	nn = max(atoi(), 1);
	noscale = 0;
}


caseab()
{
	casetm(1);
	done3(0);
}


#ifdef	NROFF
/*
 * The following routines are concerned with setting terminal options.
 *	The manner of doing this differs between research/Berkeley systems
 *	and UNIX System V systems (i.e. DOCUMENTER'S WORKBENCH)
 *	The distinction is controlled by the #define'd variable USG,
 *	which must be set by System V users.
 */


#ifdef	USG
#include <termio.h>
#define	ECHO_USG (ECHO | ECHOE | ECHOK | ECHONL)
struct termio	ttys;
#else
#include <sgtty.h>
struct	sgttyb	ttys[2];
#endif	USG

int	ttysave[2] = {-1, -1};

save_tty()			/*save any tty settings that may be changed*/
{

#ifdef	USG
	if (ioctl(0, TCGETA, &ttys) >= 0)
		ttysave[0] = ttys.c_lflag;
#else
	if (gtty(0, &ttys[0]) >= 0)
		ttysave[0] = ttys[0].sg_flags;
	if (gtty(1, &ttys[1]) >= 0)
		ttysave[1] = ttys[1].sg_flags;
#endif	USG

}


restore_tty()			/*restore tty settings from beginning*/
{

	if (ttysave[0] != -1) {
#ifdef	USG
		ttys.c_lflag = ttysave[0];
		ioctl(0, TCSETAW, &ttys);
#else
		ttys[0].sg_flags = ttysave[0];
		stty(0, &ttys[0]);
	}
	if (ttysave[1] != -1) {
		ttys[1].sg_flags = ttysave[1];
		stty(1, &ttys[1]);
#endif	USG
	}
}


set_tty()			/*this replaces the use of bset and breset*/
{

#ifndef	USG			/*for research/BSD only, reset CRMOD*/
	if (ttysave[1] == -1)
		save_tty();
	if (ttysave[1] != -1) {
		ttys[1].sg_flags &= ~CRMOD;
		stty(1, &ttys[1]);
	}
#endif	USG

}


echo_off()			/*turn off ECHO for .rd in "-q" mode*/
{
	if (ttysave[0] == -1)
		return;

#ifdef	USG
	ttys.c_lflag &= ~ECHO_USG;
	ioctl(0, TCSETAW, &ttys);
#else
	ttys[0].sg_flags &= ~ECHO;
	stty(0, &ttys[0]);
#endif	USG

}


echo_on()			/*restore ECHO after .rd in "-q" mode*/
{
	if (ttysave[0] == -1)
		return;

#ifdef	USG
	ttys.c_lflag |= ECHO_USG;
	ioctl(0, TCSETAW, &ttys);
#else
	ttys[0].sg_flags |= ECHO;
	stty(0, &ttys[0]);
#endif	USG

}
#endif	NROFF
