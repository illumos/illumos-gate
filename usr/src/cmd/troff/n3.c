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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
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

/*
 * troff3.c
 * 
 * macro and string routines, storage allocation
 */


#include "tdef.h"
#ifdef NROFF
#include "tw.h"
#endif
#include "ext.h"

#define	MHASH(x)	((x>>6)^x)&0177
struct	contab *mhash[128];	/* 128 == the 0177 on line above */
#define	blisti(i)	(((i)-ENV_BLK*BLK) / BLK)
filep	blist[NBLIST];
tchar	*argtop;
int	pagech = '%';
int	strflg;

#ifdef	INCORE
	tchar *wbuf;
	tchar corebuf[(ENV_BLK + NBLIST + 1) * BLK];
#else
	tchar wbuf[BLK];
	tchar rbuf[BLK];
#endif

caseig()
{
	register i;
	register filep oldoff;

	oldoff = offset;
	offset = 0;
	i = copyb();
	offset = oldoff;
	if (i != '.')
		control(i, 1);
}


casern()
{
	register i, j;

	lgf++;
	skip();
	if ((i = getrq()) == 0 || (oldmn = findmn(i)) < 0)
		return;
	skip();
	clrmn(findmn(j = getrq()));
	if (j) {
		munhash(&contab[oldmn]);
		contab[oldmn].rq = j;
		maddhash(&contab[oldmn]);
	}
}

maddhash(rp)
register struct contab *rp;
{
	register struct contab **hp;

	if (rp->rq == 0)
		return;
	hp = &mhash[MHASH(rp->rq)];
	rp->link = *hp;
	*hp = rp;
}

munhash(mp)
register struct contab *mp;
{	
	register struct contab *p;
	register struct contab **lp;

	if (mp->rq == 0)
		return;
	lp = &mhash[MHASH(mp->rq)];
	p = *lp;
	while (p) {
		if (p == mp) {
			*lp = p->link;
			p->link = 0;
			return;
		}
		lp = &p->link;
		p = p->link;
	}
}

mrehash()
{
	register struct contab *p;
	register i;

	for (i=0; i<128; i++)
		mhash[i] = 0;
	for (p=contab; p < &contab[NM]; p++)
		p->link = 0;
	for (p=contab; p < &contab[NM]; p++) {
		if (p->rq == 0)
			continue;
		i = MHASH(p->rq);
		p->link = mhash[i];
		mhash[i] = p;
	}
}

caserm()
{
	int j;

	lgf++;
	while (!skip() && (j = getrq()) != 0)
		clrmn(findmn(j));
	lgf--;
}


caseas()
{
	app++;
	caseds();
}


caseds()
{
	ds++;
	casede();
}


caseam()
{
	app++;
	casede();
}


casede()
{
	register i, req;
	register filep savoff;
	extern filep finds();

	if (dip != d)
		wbfl();
	req = '.';
	lgf++;
	skip();
	if ((i = getrq()) == 0)
		goto de1;
	if ((offset = finds(i)) == 0)
		goto de1;
	if (ds)
		copys();
	else 
		req = copyb();
	wbfl();
	clrmn(oldmn);
	if (newmn) {
		if (contab[newmn].rq)
			munhash(&contab[newmn]);
		contab[newmn].rq = i;
		maddhash(&contab[newmn]);
	}
	if (apptr) {
		savoff = offset;
		offset = apptr;
		wbt((tchar) IMP);
		offset = savoff;
	}
	offset = dip->op;
	if (req != '.')
		control(req, 1);
de1:
	ds = app = 0;
	return;
}


findmn(i)
register int	i;
{
	register struct contab *p;

	for (p = mhash[MHASH(i)]; p; p = p->link)
		if (i == p->rq)
			return(p - contab);
	return(-1);
}


clrmn(i)
register int	i;
{
	if (i >= 0) {
		if (contab[i].mx)
			ffree((filep)contab[i].mx);
		munhash(&contab[i]);
		contab[i].rq = 0;
		contab[i].mx = 0;
		contab[i].f = 0;
	}
}


filep finds(mn)
register int	mn;
{
	register i;
	register filep savip;
	extern filep alloc();
	extern filep incoff();

	oldmn = findmn(mn);
	newmn = 0;
	apptr = (filep)0;
	if (app && oldmn >= 0 && contab[oldmn].mx) {
		savip = ip;
		ip = (filep)contab[oldmn].mx;
		oldmn = -1;
		while ((i = rbf()) != 0)
			;
		apptr = ip;
		if (!diflg)
			ip = incoff(ip);
		nextb = ip;
		ip = savip;
	} else {
		for (i = 0; i < NM; i++) {
			if (contab[i].rq == 0)
				break;
		}
		if (i == NM || (nextb = alloc()) == 0) {
			app = 0;
			if (macerr++ > 1)
				done2(02);
			errprint(gettext("Too many (%d) string/macro names"),
					 NM);
			edone(04);
			return(offset = 0);
		}
		contab[i].mx = (unsigned) nextb;
		if (!diflg) {
			newmn = i;
			if (oldmn == -1)
				contab[i].rq = -1;
		} else {
			contab[i].rq = mn;
			maddhash(&contab[i]);
		}
	}
	app = 0;
	return(offset = nextb);
}


skip()			/*skip over blanks; return nlflg*/
{
	register tchar i;

	while (cbits(i = getch()) == ' ')
		;
	ch = i;
	return(nlflg);
}


copyb()
{
	register i, j, state;
	register tchar ii;
	int	req, k;
	filep savoff;

	if (skip() || !(j = getrq()))
		j = '.';
	req = j;
	k = j >> BYTE;
	j &= BYTEMASK;
	copyf++;
	flushi();
	nlflg = 0;
	state = 1;

/* state 0	eat up
 * state 1	look for .
 * state 2	look for first char of end macro
 * state 3	look for second char of end macro
 */

	while (1) {
		i = cbits(ii = getch());
		if (state == 3) {
			if (i == k)
				break;
			if (!k) {
				ch = ii;
				i = getach();
				ch = ii;
				if (!i)
					break;
			}
			state = 0;
			goto c0;
		}
		if (i == '\n') {
			state = 1;
			nlflg = 0;
			goto c0;
		}
		if (state == 1 && i == '.') {
			state++;
			savoff = offset;
			goto c0;
		}
		if ((state == 2) && (i == j)) {
			state++;
			goto c0;
		}
		state = 0;
c0:
		if (offset)
			wbf(ii);
	}
	if (offset) {
		wbfl();
		offset = savoff;
		wbt((tchar)0);
	}
	copyf--;
	return(req);
}


copys()
{
	register tchar i;

	copyf++;
	if (skip())
		goto c0;
	if (cbits(i = getch()) != '"')
		wbf(i);
	while (cbits(i = getch()) != '\n')
		wbf(i);
c0:
	wbt((tchar)0);
	copyf--;
}


filep alloc()		/*return free blist[] block in nextb*/
{
	register i;
	register filep j;

	for (i = 0; i < NBLIST; i++) {
		if (blist[i] == 0)
			break;
	}
	if (i == NBLIST) {
		j = 0;
	} else {
		blist[i] = -1;
		j = (filep)i * BLK + ENV_BLK * BLK;
	}
#ifdef	DEBUG
	if (debug & DB_ALLC) {
		char cc1, cc2;
		fdprintf(stderr, "alloc: ");
		if (oldmn >= 0 && oldmn < NM) {
			cc1 = contab[oldmn].rq & 0177;
			if ((cc2 = (contab[oldmn].rq >> BYTE) & 0177) == 0)
				cc2 = ' ';
			fdprintf(stderr, "oldmn %d %c%c, ", oldmn, cc1, cc2);
		}
		fdprintf(stderr, "newmn %d; nextb was %x, will be %x\n",
			newmn, nextb, j);
	}
#endif	DEBUG
	return(nextb = j);
}


ffree(i)		/*free blist[i] and blocks pointed to*/
filep i;
{
	register j;

	while (blist[j = blisti(i)] != (unsigned) ~0) {
		i = (filep) blist[j];
		blist[j] = 0;
	}
	blist[j] = 0;
}

wbt(i)
tchar i;
{
	wbf(i);
	wbfl();
}


wbf(i)			/*store i into blist[offset] (?) */
register tchar i;
{
	register j;

	if (!offset)
		return;
	if (!woff) {
		woff = offset;
#ifdef INCORE
		wbuf = &corebuf[woff];	/* INCORE only */
#endif
		wbfi = 0;
	}
	wbuf[wbfi++] = i;
	if (!((++offset) & (BLK - 1))) {
		wbfl();
		j = blisti(--offset);
		if (j < 0 || j >= NBLIST) {
			errprint(gettext("Out of temp file space"));
			done2(01);
		}
		if (blist[j] == (unsigned) ~0) {
			if (alloc() == 0) {
				errprint(gettext("Out of temp file space"));
				done2(01);
			}
			blist[j] = (unsigned)(nextb);
		}
		offset = ((filep)blist[j]);
	}
	if (wbfi >= BLK)
		wbfl();
}


wbfl()			/*flush current blist[] block*/
{
	if (woff == 0)
		return;
#ifndef INCORE
	lseek(ibf, ((long)woff) * sizeof(tchar), 0);
	write(ibf, (char *)wbuf, wbfi * sizeof(tchar));
#endif
	if ((woff & (~(BLK - 1))) == (roff & (~(BLK - 1))))
		roff = -1;
	woff = 0;
}


tchar rbf()		/*return next char from blist[] block*/
{
	register tchar i;
	register filep j, p;
	extern filep incoff();

	if (ip == NBLIST*BLK) {		/* for rdtty */
		if (j = rdtty())
			return(j);
		else
			return(popi());
	}
	/* this is an inline expansion of rbf0: dirty! */
#ifndef INCORE
	j = ip & ~(BLK - 1);
	if (j != roff) {
		roff = j;
		lseek(ibf, (long)j * sizeof(tchar), 0);
		if (read(ibf, (char *)rbuf, BLK * sizeof(tchar)) <= 0)
			i = 0;
		else
			i = rbuf[ip & (BLK-1)];
	} else
		i = rbuf[ip & (BLK-1)];
#else
	i = corebuf[ip];
#endif
	/* end of rbf0 */
	if (i == 0) {
		if (!app)
			i = popi();
		return(i);
	}
	/* this is an inline expansion of incoff: also dirty */
	p = ++ip;
	if ((p & (BLK - 1)) == 0) {
		if ((ip = blist[blisti(p-1)]) == (unsigned) ~0) {
			errprint(gettext("Bad storage allocation"));
			ip = 0;
			done2(-5);
		}
		/* this was meant to protect against people removing
		 * the macro they were standing on, but it's too
		 * sensitive to block boundaries.
		 * if (ip == 0) {
		 *	errprint(gettext("Block removed while in use"));
		 *	done2(-6);
		 * }
		 */
	}
	return(i);
}


tchar rbf0(p)
register filep p;
{
#ifndef INCORE
	register filep i;

	if ((i = p & ~(BLK - 1)) != roff) {
		roff = i;
		lseek(ibf, (long)roff * sizeof(tchar), 0);
		if (read(ibf, (char *)rbuf, BLK * sizeof(tchar)) == 0)
			return(0);
	}
	return(rbuf[p & (BLK-1)]);
#else
	return(corebuf[p]);
#endif
}


filep incoff(p)		/*get next blist[] block*/
register filep p;
{
	p++;
	if ((p & (BLK - 1)) == 0) {
		if ((p = blist[blisti(p-1)]) == (unsigned) ~0) {
			errprint(gettext("Bad storage allocation"));
			done2(-5);
		}
	}
	return(p);
}


tchar popi()
{
	register struct s *p;

	if (frame == stk)
		return(0);
	if (strflg)
		strflg--;
	p = nxf = frame;
	p->nargs = 0;
	frame = p->pframe;
	ip = p->pip;
	pendt = p->ppendt;
	lastpbp = p->lastpbp;
	return(p->pch);
}

/*
 *	test that the end of the allocation is above a certain location
 *	in memory
 */
#define SPACETEST(base, size) while ((enda - (size)) <= (char *)(base)){setbrk(DELTA);}

pushi(newip, mname)
filep newip;
int mname;
{
	register struct s *p;
	extern char *setbrk();

	SPACETEST(nxf, sizeof(struct s));
	p = nxf;
	p->pframe = frame;
	p->pip = ip;
	p->ppendt = pendt;
	p->pch = ch;
	p->lastpbp = lastpbp;
	p->mname = mname;
	lastpbp = pbp;
	pendt = ch = 0;
	frame = nxf;
	if (nxf->nargs == 0) 
		nxf += 1;
	else 
		nxf = (struct s *)argtop;
	return(ip = newip);
}


char	*setbrk(x)
int	x;
{
	register char	*i, *k;
	register j;
	char	*sbrk();

	if ((i = sbrk(x)) == (char *) -1) {
		errprint(gettext("Core limit reached"));
		edone(0100);
	}
	if (j = (unsigned)i % sizeof(int)) {	/*check alignment for 3B*/
		j = sizeof(int) - j;		/*only init calls should need this*/
		if ((k = sbrk(j)) == (char *) -1) {
			errprint("Core limit reached");
			edone(0100);
		}
		if (k != i + x) {	/*there must have been an intervening sbrk*/
			errprint ("internal error in setbrk: i=%x, j=%d, k=%x",
				i, j, k);
			edone(0100);
		}
		i += j;
	}
	enda = i + x;
	return(i);
}


getsn()
{
	register i;

	if ((i = getach()) == 0)
		return(0);
	if (i == '(')
		return(getrq());
	else 
		return(i);
}


setstr()
{
	register i, j;

	lgf++;
	if ((i = getsn()) == 0 || (j = findmn(i)) == -1 || !contab[j].mx) {
		lgf--;
		return(0);
	} else {
		SPACETEST(nxf, sizeof(struct s));
		nxf->nargs = 0;
		strflg++;
		lgf--;
		return pushi((filep)contab[j].mx, i);
	}
}



collect()
{
	register j;
	register tchar i;
	register tchar *strp;
	tchar * lim;
	tchar * *argpp, **argppend;
	int	quote;
	struct s *savnxf;

	copyf++;
	nxf->nargs = 0;
	savnxf = nxf;
	if (skip())
		goto rtn;

	{
		char *memp;
		memp = (char *)savnxf;
		/*
		 *	1 s structure for the macro descriptor
		 *	APERMAC tchar *'s for pointers into the strings
		 *	space for the tchar's themselves
		 */
		memp += sizeof(struct s);
		/*
		 *	CPERMAC (the total # of characters for ALL arguments)
		 *	to a macros, has been carefully chosen
		 *	so that the distance between stack frames is < DELTA 
		 */
#define	CPERMAC	200
#define	APERMAC	9
		memp += APERMAC * sizeof(tchar *);
		memp += CPERMAC * sizeof(tchar);
		nxf = (struct s*)memp;
	}
	lim = (tchar *)nxf;
	argpp = (tchar **)(savnxf + 1);
	argppend = &argpp[APERMAC];
	SPACETEST(argppend, sizeof(tchar *));
	strp = (tchar *)argppend;
	/*
	 *	Zero out all the string pointers before filling them in.
	 */
	for (j = 0; j < APERMAC; j++){
		argpp[j] = (tchar *)0;
	}
#if 0
	errprint("savnxf=0x%x,nxf=0x%x,argpp=0x%x,strp=argppend=0x%x,lim=0x%x,enda=0x%x",
		savnxf, nxf, argpp, strp, lim, enda);
#endif 0
	strflg = 0;
	while ((argpp != argppend) && (!skip())) {
		*argpp++ = strp;
		quote = 0;
		if (cbits(i = getch()) == '"')
			quote++;
		else 
			ch = i;
		while (1) {
			i = getch();
			if (nlflg || (!quote && cbits(i) == ' '))
				break;
			if (   quote
			    && (cbits(i) == '"')
			    && (cbits(i = getch()) != '"')) {
				ch = i;
				break;
			}
			*strp++ = i;
			if (strflg && strp >= lim) {
#if 0
				errprint("strp=0x%x, lim = 0x%x",
					strp, lim);
#endif 0
				errprint(gettext("Macro argument too long"));
				copyf--;
				edone(004);
			}
			SPACETEST(strp, 3 * sizeof(tchar));
		}
		*strp++ = 0;
	}
	nxf = savnxf;
	nxf->nargs = argpp - (tchar **)(savnxf + 1);
	argtop = strp;
rtn:
	copyf--;
}


seta()
{
	register i;

	i = cbits(getch()) - '0';
	if (i > 0 && i <= APERMAC && i <= frame->nargs)
		pushback(*(((tchar **)(frame + 1)) + i - 1));
}


caseda()
{
	app++;
	casedi();
}


casedi()
{
	register i, j;
	register *k;

	lgf++;
	if (skip() || (i = getrq()) == 0) {
		if (dip != d)
			wbt((tchar)0);
		if (dilev > 0) {
			numtab[DN].val = dip->dnl;
			numtab[DL].val = dip->maxl;
			dip = &d[--dilev];
			offset = dip->op;
		}
		goto rtn;
	}
	if (++dilev == NDI) {
		--dilev;
		errprint(gettext("Diversions nested too deep"));
		edone(02);
	}
	if (dip != d)
		wbt((tchar)0);
	diflg++;
	dip = &d[dilev];
	dip->op = finds(i);
	dip->curd = i;
	clrmn(oldmn);
	k = (int *) & dip->dnl;
	for (j = 0; j < 10; j++)
		k[j] = 0;	/*not op and curd*/
rtn:
	app = 0;
	diflg = 0;
}


casedt()
{
	lgf++;
	dip->dimac = dip->ditrap = dip->ditf = 0;
	skip();
	dip->ditrap = vnumb((int *)0);
	if (nonumb)
		return;
	skip();
	dip->dimac = getrq();
}


casetl()
{
	register j;
	int w[3];
	tchar buf[LNSIZE];
	register tchar *tp;
	tchar i, delim;

	dip->nls = 0;
	skip();
	if (ismot(delim = getch())) {
		ch = delim;
		delim = '\'';
	} else 
		delim = cbits(delim);
	tp = buf;
	numtab[HP].val = 0;
	w[0] = w[1] = w[2] = 0;
	j = 0;
	while (cbits(i = getch()) != '\n') {
		if (cbits(i) == cbits(delim)) {
			if (j < 3)
				w[j] = numtab[HP].val;
			numtab[HP].val = 0;
			j++;
			*tp++ = 0;
		} else {
			if (cbits(i) == pagech) {
				setn1(numtab[PN].val, numtab[findr('%')].fmt,
				      i&SFMASK);
				continue;
			}
			numtab[HP].val += width(i);
			if (tp < &buf[LNSIZE-10])
				*tp++ = i;
		}
	}
	if (j<3)
		w[j] = numtab[HP].val;
	*tp++ = 0;
	*tp++ = 0;
	*tp++ = 0;
	tp = buf;
#ifdef NROFF
	horiz(po);
#endif
	while (i = *tp++)
		pchar(i);
	if (w[1] || w[2])
		horiz(j = quant((lt - w[1]) / 2 - w[0], HOR));
	while (i = *tp++)
		pchar(i);
	if (w[2]) {
		horiz(lt - w[0] - w[1] - w[2] - j);
		while (i = *tp++)
			pchar(i);
	}
	newline(0);
	if (dip != d) {
		if (dip->dnl > dip->hnl)
			dip->hnl = dip->dnl;
	} else {
		if (numtab[NL].val > dip->hnl)
			dip->hnl = numtab[NL].val;
	}
}


casepc()
{
	pagech = chget(IMP);
}


casepm()
{
	register i, k;
	register char	*p;
	int	xx, cnt, tcnt, kk, tot;
	filep j;
	char	pmline[10];

	kk = cnt = tcnt = 0;
	tot = !skip();
	for (i = 0; i < NM; i++) {
		if ((xx = contab[i].rq) == 0 || contab[i].mx == 0)
			continue;
		tcnt++;
		p = pmline;
		j = (filep) contab[i].mx;
		k = 1;
		while ((j = blist[blisti(j)]) != (unsigned) ~0) {
			k++; 
		}
		cnt++;
		kk += k;
		if (!tot) {
			*p++ = xx & 0177;
			if (!(*p++ = (xx >> BYTE) & 0177))
				*(p - 1) = ' ';
			*p++ = 0;
			fdprintf(stderr, "%s %d\n", pmline, k);
		}
	}
	fdprintf(stderr, "pm: total %d, macros %d, space %d\n", tcnt, cnt, kk);
}

stackdump()	/* dumps stack of macros in process */
{
	struct s *p;

	if (frame != stk) {
		for (p = frame; p != stk; p = p->pframe)
			fdprintf(stderr, "%c%c ", p->mname&0177, (p->mname>>BYTE)&0177);
		fdprintf(stderr, "\n");
	}
}
