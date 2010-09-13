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
setsize(char *p)	/* set size as found in p */
{
	if (*p == '+')
		ps += atoi(p+1);
	else if (*p == '-')
		ps -= atoi(p+1);
	else
		ps = atoi(p);
	if (dbg) printf(".\tsetsize %s; ps = %d\n", p, ps);
}

void
size(int p1, int p2)
{
	/* old size in p1, new in ps */

	int effps, effp1;

	yyval = p2;
	if (dbg)
		printf(".\tb:sb: S%d <- \\s%d S%d \\s%d; b=%d, h=%d\n",
		    yyval, ps, p2, p1, ebase[yyval], eht[yyval]);
	effps = EFFPS(ps);
	effp1 = EFFPS(p1);
	printf(".ds %d \\s%d\\*(%d\\s%d\n", yyval, effps, p2, effp1);
	ps = p1;
}

void
globsize(void)
{
	char temp[20];

	getstr(temp, 20);
	if (temp[0] == '+')
		gsize += atoi(temp+1);
	else if (temp[0] == '-')
		gsize -= atoi(temp+1);
	else
		gsize = atoi(temp);
	yyval = eqnreg = 0;
	setps(gsize);
	ps = gsize;
	if (gsize >= 12)	/* sub and sup size change */
		deltaps = gsize / 4;
	else
		deltaps = gsize / 3;
}
