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
#include "e.def"

void
move(int dir, int amt, int p)
{
	int a;

	yyval = p;
#ifndef NEQN
	a = VERT(EM(amt/100.0, EFFPS(ps)));
#else	/* NEQN */
	a = VERT((amt+49)/50);	/* nearest number of half-lines */
#endif	/* NEQN */
	printf(".ds %d ", yyval);
	if (dir == FWD || dir == BACK)	/* fwd, back */
		printf("\\h'%s%du'\\*(%d\n", (dir == BACK) ? "-" : "", a, p);
	else if (dir == UP)
		printf("\\v'-%du'\\*(%d\\v'%du'\n", a, p, a);
	else if (dir == DOWN)
		printf("\\v'%du'\\*(%d\\v'-%du'\n", a, p, a);
	if (dbg)
		printf(".\tmove %d dir %d amt %d; h=%d b=%d\n",
		    p, dir, a, eht[yyval], ebase[yyval]);
}
