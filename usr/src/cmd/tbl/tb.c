/*
 * Copyright 1991 Sun Microsystems, Inc.  All rights reserved.
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

 /* tb.c: check which entries exist, also storage allocation */
# include "t..c"
#include <stdlib.h>

void
checkuse(void)
{
int i,c, k;
for(c=0; c<ncol; c++)
	{
	used[c]=lused[c]=rused[c]=0;
	for(i=0; i<nlin; i++)
		{
		if (instead[i] || fullbot[i]) continue;
		k = ctype(i,c);
		if (k== '-' || k == '=') continue;
		if ((k=='n'||k=='a'))
			{
			rused[c]|= real(table[i][c].rcol);
			if( !real(table[i][c].rcol))
			used[c] |= real(table[i][c].col);
			if (table[i][c].rcol)
			lused[c] |= real(table[i][c].col);
			}
		else
			used[c] |= real(table[i][c].col);
		}
	}
}

int
real(char *s)
{
if (s==0) return(0);
if (!point(s)) return(1);
if (*s==0) return(0);
return(1);
}

int spcount = 0;

# define MAXVEC 20

char *spvecs[MAXVEC];

char *
chspace(void)
{
char *pp;
if (spvecs[spcount])
	return(spvecs[spcount++]);
if (spcount>=MAXVEC)
	error(gettext("Too many characters in table"));
spvecs[spcount++]= pp = calloc(MAXCHS+MAXSTR,1);
if (pp == 0)
	error(gettext("no space for characters"));
return(pp);
}

# define MAXPC 50

char *thisvec;
int tpcount = -1;
char *tpvecs[MAXPC];

int *
alocv(int n)
{
int *tp, *q;
if (tpcount<0 || thisvec+n > tpvecs[tpcount]+MAXCHS)
	{
	tpcount++;
	if (tpvecs[tpcount]==0)
		{
		tpvecs[tpcount] = calloc(MAXCHS,1);
		}
	thisvec = tpvecs[tpcount];
	if (thisvec == 0)
		error(gettext("no space for vectors"));
	}
tp=(int *)thisvec;
thisvec+=n;
for(q=tp; q<(int *)thisvec; q++)
	*q=0;
return(tp);
}

void
release(void)
{
extern char *exstore;
/* give back unwanted space in some vectors */
spcount=0;
tpcount= -1;
exstore=0;
}
