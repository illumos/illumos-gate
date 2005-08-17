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
#include <locale.h>

void
funny(int n)
{
	char *f;

	yyval = oalloc();
	switch (n) {
	case SUM:
		f = "\\(*S"; break;
	case UNION:
		f = "\\(cu"; break;
	case INTER:	/* intersection */
		f = "\\(ca"; break;
	case PROD:
		f = "\\(*P"; break;
	default:
		(void) error(FATAL, gettext("funny type %d in funny"), n);
	}
#ifndef NEQN
	printf(".ds %d \\s%d\\v'.3m'\\s+5%s\\s-5\\v'-.3m'\\s%d\n",
	    yyval, ps, f, ps);
	eht[yyval] = VERT(EM(1.0, ps+5) - EM(0.2, ps));
	ebase[yyval] = VERT(EM(0.3, ps));
#else	/* NEQN */
	printf(".ds %d %s\n", yyval, f);
	eht[yyval] = VERT(2);
	ebase[yyval] = 0;
#endif	/* NEQN */
	if (dbg)
		printf(".\tfunny: S%d <- %s; h=%d b=%d\n",
		    yyval, f, eht[yyval], ebase[yyval]);
	lfont[yyval] = rfont[yyval] = ROM;
}
