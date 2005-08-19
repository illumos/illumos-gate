/*
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
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

 /* t5.c: read data for table */
# include "t..c"

void	permute(void);

void
gettbl(void)
{
int icol, ch;
cstore=cspace= chspace();
textflg=0;
for (nlin=nslin=0; gets1(cstore, MAXSTR); nlin++)
	{
	stynum[nlin]=nslin;
	if (prefix(".TE", cstore))
		{
		leftover=0;
		break;
		}
	if (prefix(".TC", cstore) || prefix(".T&", cstore))
		{
		readspec();
		nslin++;
		}
	if (nlin>=MAXLIN)
		{
		leftover=cstore;
		break;
		}
	fullbot[nlin]=0;
	if (cstore[0] == '.' && !isdigit((unsigned char)cstore[1]))
		{
		instead[nlin] = cstore;
		while (*cstore++);
		continue;
		}
	else instead[nlin] = 0;
	if (nodata(nlin))
		{
		if (ch = oneh(nlin))
			fullbot[nlin]= ch;
		nlin++;
		nslin++;
		instead[nlin]=(char *)0;
		fullbot[nlin]=0;
		}
	table[nlin] = (struct colstr *) alocv((ncol+2)*sizeof(table[0][0]));
	if (cstore[1]==0)
	switch(cstore[0])
		{
		case '_': fullbot[nlin]= '-'; continue;
		case '=': fullbot[nlin]= '='; continue;
		}
	stynum[nlin] = nslin;
	nslin = min(nslin+1, nclin-1);
	for (icol = 0; icol <ncol; icol++)
		{
		table[nlin][icol].col = cstore;
		table[nlin][icol].rcol=0;
		ch=1;
		if (match(cstore, "T{")) /* text follows */
			/* get_text was originally gettext and was renamed */
			table[nlin][icol].col =
				(char *)get_text(cstore, nlin, icol,
					font[stynum[nlin]][icol],
					csize[stynum[nlin]][icol]);
		else
			{
			for(; (ch= *cstore) != '\0' && ch != tab; cstore++)
					;
			*cstore++ = '\0';
			switch(ctype(nlin,icol)) /* numerical or alpha, subcol */
				{
				case 'n':
					table[nlin][icol].rcol =
					    (char *)maknew(table[nlin][icol].col);
					break;
				case 'a':
					table[nlin][icol].rcol = table[nlin][icol].col;
					table[nlin][icol].col = "";
					break;
				}
			}
		while (ctype(nlin,icol+1)== 's') /* spanning */
			table[nlin][++icol].col = "";
		if (ch == '\0') break;
		}
	while (++icol <ncol+2)
		{
		table[nlin][icol].col = "";
		table [nlin][icol].rcol=0;
		}
	while (*cstore != '\0')
		 cstore++;
	if (cstore-cspace > MAXCHS)
		cstore = cspace = chspace();
	}
last = cstore;
permute();
if (textflg) untext();
return;
}

int
nodata(int il)
{
int c;
for (c=0; c<ncol;c++)
	{
	switch(ctype(il,c))
		{
		case 'c': case 'n': case 'r': case 'l': case 's': case 'a':
			return(0);
		}
	}
return(1);
}

int
oneh(int lin)
{
int k, icol;
k = ctype(lin,0);
for(icol=1; icol<ncol; icol++)
	{
	if (k != ctype(lin,icol))
		return(0);
	}
return(k);
}

# define SPAN "\\^"

void
permute(void)
{
int irow, jcol, is;
char *start, *strig;
for(jcol=0; jcol<ncol; jcol++)
	{
	for(irow=1; irow<nlin; irow++)
		{
		if (vspand(irow,jcol,0))
			{
			is = prev(irow);
			if (is<0)
				error(gettext("Vertical spanning in first row not allowed"));
			start = table[is][jcol].col;
			strig = table[is][jcol].rcol;
			while (irow<nlin &&vspand(irow,jcol,0))
				irow++;
			table[--irow][jcol].col = start;
			table[irow][jcol].rcol = strig;
			while (is<irow)
				{
				table[is][jcol].rcol =0;
				table[is][jcol].col= SPAN;
				is = next(is);
				}
			}
		}
	}
}

int
vspand(int ir, int ij, int ifform)
{
if (ir<0) return(0);
if (ir>=nlin)return(0);
if (instead[ir]) return(0);
if (ifform==0 && ctype(ir,ij)=='^') return(1);
if (table[ir]==0) return(0);
if (table[ir][ij].rcol!=0) return(0);
if (fullbot[ir]) return(0);
return(vspen(table[ir][ij].col));
}

int
vspen(char *s)
{
if (s==0) return(0);
if (!point(s)) return(0);
return(match(s, SPAN));
}
