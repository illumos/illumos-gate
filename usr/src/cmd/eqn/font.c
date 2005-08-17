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
setfont(char ch1)
{
	/* use number '1', '2', '3' for roman, italic, bold */
	yyval = ft;
	if (ch1 == 'r' || ch1 == 'R')
		ft = ROM;
	else if (ch1 == 'i' || ch1 == 'I')
		ft = ITAL;
	else if (ch1 == 'b' || ch1 == 'B')
		ft = BLD;
	else
		ft = ch1;
	printf(".ft %c\n", ft);
#ifndef NEQN
	if (dbg) printf(".\tsetfont %c %c\n", ch1, ft);
#else	/* NEQN */
	if (dbg) printf(".\tsetfont %c\n", ft);
#endif	/* NEQN */
}

void
font(int p1, int p2)
{
		/* old font in p1, new in ft */
	yyval = p2;
	lfont[yyval] = rfont[yyval] = ft == ITAL ? ITAL : ROM;
	if (dbg)
		printf(".\tb:fb: S%d <- \\f%c S%d \\f%c b=%d,h=%d,lf=%c,"
		    "rf=%c\n", yyval, ft, p2, p1, ebase[yyval], eht[yyval],
		    lfont[yyval], rfont[yyval]);
	printf(".ds %d \\f%c\\*(%d\\f%c\n", yyval, ft, p2, p1);
	ft = p1;
	printf(".ft %c\n", ft);
}

void
fatbox(int p)
{
	yyval = p;
	nrwid(p, ps, p);
	printf(".ds %d \\*(%d\\h'-\\n(%du+0.05m'\\*(%d\n", p, p, p, p);
	if (dbg) printf(".\tfat %d, sh=0.05m\n", p);
}

void
globfont(void)
{
	char temp[20];

	(void) getstr(temp, 20);
	yyval = eqnreg = 0;
	gfont = temp[0];
	switch (gfont) {
	case 'r': case 'R':
		gfont = '1';
		break;
	case 'i': case 'I':
		gfont = '2';
		break;
	case 'b': case 'B':
		gfont = '3';
		break;
	}
	printf(".ft %c\n", gfont);
	ft = gfont;
}
