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
sqrt(int p2)
{
#ifndef NEQN
	int nps;

	nps = EFFPS(((eht[p2]*9)/10+(resolution/POINT-1))/(resolution/POINT));
#endif	/* NEQN */
	yyval = p2;
#ifndef NEQN
	eht[yyval] = VERT(EM(1.2, nps));
	if (dbg)
		printf(".\tsqrt: S%d <- S%d;b=%d, h=%d\n",
		    yyval, p2, ebase[yyval], eht[yyval]);
	if (rfont[yyval] == ITAL)
		printf(".as %d \\|\n", yyval);
#endif	/* NEQN */
	nrwid(p2, ps, p2);
#ifndef NEQN
	printf(".ds %d \\v'%du'\\s%d\\v'-.2m'\\(sr\\l'\\n(%du\\"
	    "(rn'\\v'.2m'\\s%d", yyval, ebase[p2], nps, p2, ps);
	printf("\\v'%du'\\h'-\\n(%du'\\*(%d\n", -ebase[p2], p2, p2);
	lfont[yyval] = ROM;
#else	/* NEQN */
	printf(".ds %d \\v'%du'\\e\\L'%du'\\l'\\n(%du'",
	    p2, ebase[p2], -eht[p2], p2);
	printf("\\v'%du'\\h'-\\n(%du'\\*(%d\n", eht[p2]-ebase[p2], p2, p2);
	eht[p2] += VERT(1);
	if (dbg)
		printf(".\tsqrt: S%d <- S%d;b=%d, h=%d\n",
		    p2, p2, ebase[p2], eht[p2]);
#endif	/* NEQN */
}
