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

extern int max();

void brack(int, char *, char *, char *);

void
paren(int leftc, int p1, int rightc)
{
	int n, m, h1, j, b1, v;
	h1 = eht[p1]; b1 = ebase[p1];
	yyval = p1;
#ifndef NEQN
	lfont[yyval] = rfont[yyval] = 0;
	n = (h1 + EM(1.0, EFFPS(ps)) - 1) / EM(1.0, EFFPS(ps));
#else	/* NEQN */
	n = max(b1+VERT(1), h1-b1-VERT(1)) / VERT(1);
#endif	/* NEQN */
	if (n < 2) n = 1;
	m = n-2;
	if (leftc == '{' || rightc == '}') {
		if ((n % 2) == 0) {
			n++;
		}
		if (n < 3) n = 3;
		m = n-3;
	}
#ifndef NEQN
	eht[yyval] = VERT(EM(n, ps));
	ebase[yyval] = b1 + (eht[yyval]-h1)/2;
	v = b1 - h1/2 + VERT(EM(0.4, ps));
#else	/* NEQN */
	eht[yyval] = VERT(2 * n);
	ebase[yyval] = (n)/2 * VERT(2);
	if (n%2 == 0)
		ebase[yyval] -= VERT(1);
	v = b1 - h1/2 + VERT(1);
#endif	/* NEQN */
	printf(".ds %d \\|\\v'%du'", yyval, v);
	switch (leftc) {
		case 'n':	/* nothing */
		case '\0':
			break;
		case 'f':	/* floor */
			if (n <= 1)
				printf("\\(lf");
			else
				brack(m, "\\(bv", "\\(bv", "\\(lf");
			break;
		case 'c':	/* ceiling */
			if (n <= 1)
				printf("\\(lc");
			else
				brack(m, "\\(lc", "\\(bv", "\\(bv");
			break;
		case '{':
			printf("\\b'\\(lt");
			for (j = 0; j < m; j += 2) printf("\\(bv");
			printf("\\(lk");
			for (j = 0; j < m; j += 2) printf("\\(bv");
			printf("\\(lb'");
			break;
		case '(':
			brack(m, "\\(lt", "\\(bv", "\\(lb");
			break;
		case '[':
			brack(m, "\\(lc", "\\(bv", "\\(lf");
			break;
		case '|':
			brack(m, "\\(bv", "\\(bv", "\\(bv");
			break;
		default:
			brack(m, (char *)&leftc, (char *)&leftc,
			    (char *)&leftc);
			break;
		}
	printf("\\v'%du'\\*(%d", -v, p1);
	if (rightc) {
		printf("\\|\\v'%du'", v);
		switch (rightc) {
			case 'f':	/* floor */
				if (n <= 1)
					printf("\\(rf");
				else
					brack(m, "\\(bv", "\\(bv", "\\(rf");
				break;
			case 'c':	/* ceiling */
				if (n <= 1)
					printf("\\(rc");
				else
					brack(m, "\\(rc", "\\(bv", "\\(bv");
				break;
			case '}':
				printf("\\b'\\(rt");
				for (j = 0; j < m; j += 2) printf("\\(bv");
				printf("\\(rk");
				for (j = 0; j < m; j += 2) printf("\\(bv");
				printf("\\(rb'");
				break;
			case ']':
				brack(m, "\\(rc", "\\(bv", "\\(rf");
				break;
			case ')':
				brack(m, "\\(rt", "\\(bv", "\\(rb");
				break;
			case '|':
				brack(m, "\\(bv", "\\(bv", "\\(bv");
				break;
			default:
				brack(m, (char *)&rightc, (char *)&rightc,
				    (char *)&rightc);
				break;
		}
		printf("\\v'%du'", -v);
	}
	printf("\n");
	if (dbg)
		printf(".\tcurly: h=%d b=%d n=%d v=%d l=%c, r=%c\n",
		    eht[yyval], ebase[yyval], n, v, leftc, rightc);
}

void
brack(int m, char *t, char *c, char *b)
{
	int j;
	printf("\\b'%s", t);
	for (j = 0; j < m; j++)
		printf("%s", c);
	printf("%s'", b);
}
