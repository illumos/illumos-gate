/*
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * Copyright (c) 1980 Regents of the University of California.
 * All rights reserved.  The Berkeley Software License Agreement
 * specifies the terms and conditions for redistribution.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "sh.h"
#include "sh.tconst.h"

struct Hist *enthist(int, struct wordent *, bool);
void	hfree(struct Hist *);
void	dohist1(struct Hist *, int *, int, int);
void	phist(struct Hist *, int);

/*
 * C shell
 */

void
savehist(struct wordent *sp)
{
	struct Hist *hp, *np;
	int histlen = 0;
	tchar *cp;

#ifdef TRACE
	tprintf("TRACE- savehist()\n");
#endif
	/* throw away null lines */
	if (sp->next->word[0] == '\n')
		return;
	cp = value(S_history /*"history"*/);
	if (*cp) {
		tchar *p = cp;

		while (*p) {
			if (!digit(*p)) {
				histlen = 0;
				break;
			}
			histlen = histlen * 10 + *p++ - '0';
		}
	}
	for (hp = &Histlist; np = hp->Hnext;)
		if (eventno - np->Href >= histlen || histlen == 0)
			hp->Hnext = np->Hnext, hfree(np);
		else
			hp = np;
	(void) enthist(++eventno, sp, 1);
}

struct Hist *
enthist(int event, struct wordent *lp, bool docopy)
{
	struct Hist *np;

#ifdef TRACE
	tprintf("TRACE- enthist()\n");
#endif
	np = (struct Hist *) xalloc(sizeof *np);
	np->Hnum = np->Href = event;
	if (docopy)
		copylex(&np->Hlex, lp);
	else {
		np->Hlex.next = lp->next;
		lp->next->prev = &np->Hlex;
		np->Hlex.prev = lp->prev;
		lp->prev->next = &np->Hlex;
	}
	np->Hnext = Histlist.Hnext;
	Histlist.Hnext = np;
	return (np);
}

void
hfree(struct Hist *hp)
{
#ifdef TRACE
	tprintf("TRACE- hfree()\n");
#endif

	freelex(&hp->Hlex);
	xfree( (tchar *)hp);
}

void
dohist(tchar **vp)
{
	int n, rflg = 0, hflg = 0;
#ifdef TRACE
	tprintf("TRACE- dohist()\n");
#endif
	if (getn(value(S_history /*"history"*/)) == 0)
		return;
	if (setintr)
		(void) sigsetmask(sigblock(0) & ~sigmask(SIGINT));
	while (*++vp && **vp == '-') {
		tchar *vp2 = *vp;

		while (*++vp2)
			switch (*vp2) {
			case 'h':
				hflg++;
				break;
			case 'r':
				rflg++;
				break;
			case '-':	/* ignore multiple '-'s */
				break;
			default:
				printf("Unknown flag: -%c\n", *vp2);
				error("Usage: history [-rh] [# number of events]");
			}
	}
	if (*vp)
		n = getn(*vp);
	else {
		n = getn(value(S_history /*"history"*/));
	}
	dohist1(Histlist.Hnext, &n, rflg, hflg);
}

void
dohist1(struct Hist *hp, int *np, int rflg, int hflg)
{
	bool print = (*np) > 0;
#ifdef TRACE
	tprintf("TRACE- dohist1()\n");
#endif
top:
	if (hp == 0)
		return;
	(*np)--;
	hp->Href++;
	if (rflg == 0) {
		dohist1(hp->Hnext, np, rflg, hflg);
		if (print)
			phist(hp, hflg);
		return;
	}
	if (*np >= 0)
		phist(hp, hflg);
	hp = hp->Hnext;
	goto top;
}

void
phist(struct Hist *hp, int hflg)
{
#ifdef TRACE
	tprintf("TRACE- phist()\n");
#endif

	if (hflg == 0)
		printf("%6d\t", hp->Hnum);
	prlex(&hp->Hlex);
}
