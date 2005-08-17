/*
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * Copyright (c) 1980 Regents of the University of California.
 * All rights reserved. The Berkeley software License Agreement
 * specifies the terms and conditions for redistribution.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "e.h"

void
lpile(int type, int p1, int p2)
{
	int bi, hi, i, gap, h, b, nlist, nlist2, mid;
	yyval = oalloc();
#ifndef NEQN
	gap = VERT(EM(0.4, ps)); /* 4/10 m between blocks */
#else	/* NEQN */
	gap = VERT(1);
#endif	/* NEQN */
	if (type == '-') gap = 0;
	nlist = p2 - p1;
	nlist2 = (nlist+1)/2;
	mid = p1 + nlist2 -1;
	h = 0;
	for (i = p1; i < p2; i++)
		h += eht[lp[i]];
	eht[yyval] = h + (nlist-1)*gap;
	b = 0;
	for (i = p2-1; i > mid; i--)
		b += eht[lp[i]] + gap;
#ifndef NEQN
	ebase[yyval] = (nlist%2) ? b + ebase[lp[mid]]
	    : b - VERT(EM(0.5, ps)) - gap;
#else	/* NEQN */
	ebase[yyval] = (nlist%2) ? b + ebase[lp[mid]]
	    : b - VERT(1) - gap;
#endif	/* NEQN */
	if (dbg) {
		printf(".\tS%d <- %c pile of:", yyval, type);
		for (i = p1; i < p2; i++)
			printf(" S%d", lp[i]);
		printf(";h=%d b=%d\n", eht[yyval], ebase[yyval]);
	}
	nrwid(lp[p1], ps, lp[p1]);
	printf(".nr %d \\n(%d\n", yyval, lp[p1]);
	for (i = p1+1; i < p2; i++) {
		nrwid(lp[i], ps, lp[i]);
		printf(".if \\n(%d>\\n(%d .nr %d \\n(%d\n",
		    lp[i], yyval, yyval, lp[i]);
	}
	printf(".ds %d \\v'%du'\\h'%du*\\n(%du'\\\n", yyval, ebase[yyval],
	    type == 'R' ? 1 : 0, yyval);
	for (i = p2-1; i >= p1; i--) {
		hi = eht[lp[i]];
		bi = ebase[lp[i]];
	switch (type) {

	case 'L':
		printf("\\v'%du'\\*(%d\\h'-\\n(%du'\\v'0-%du'\\\n",
		    -bi, lp[i], lp[i], hi-bi+gap);
		continue;
	case 'R':
		printf("\\v'%du'\\h'-\\n(%du'\\*(%d\\v'0-%du'\\\n",
		    -bi, lp[i], lp[i], hi-bi+gap);
		continue;
	case 'C':
	case '-':
		printf("\\v'%du'\\h'\\n(%du-\\n(%du/2u'\\*(%d",
		    -bi, yyval, lp[i], lp[i]);
		printf("\\h'-\\n(%du-\\n(%du/2u'\\v'0-%du'\\\n",
		    yyval, lp[i], hi-bi+gap);
		continue;
		}
	}
	printf("\\v'%du'\\h'%du*\\n(%du'\n", eht[yyval]-ebase[yyval]+gap,
	    type != 'R' ? 1 : 0, yyval);
	for (i = p1; i < p2; i++)
		ofree(lp[i]);
	lfont[yyval] = rfont[yyval] = 0;
}
