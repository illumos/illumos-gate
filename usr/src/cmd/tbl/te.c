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

 /* te.c: error message control, input line count */
#include "t..c"
#include <locale.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>

void
error(char *s)
{
	(void) fprintf(stderr, gettext("\n%s: line %d: %s\n"), ifile, iline, s);
	(void) fprintf(stderr, gettext("tbl quits\n"));
	exit(1);
}

char *
gets1(char *s, int len)
{
char *p;
int nbl;
while(len > 0)
	{
	iline++;
	while ((p = fgets(s,len,tabin))==0)
		{
		if (swapin()==0)
			return((char *)0);
		}

	while (*s) s++;
	s--;
	if (*s == '\n') {
		*s-- = '\0';
	} else {
		if (!feof(tabin)) {
			if (ferror(tabin))
				error(strerror(errno));
			else
				error(gettext("Line too long"));
		}
	}

	for(nbl=0; *s == '\\' && s>p; s--)
		nbl++;
	if (linstart && nbl % 2) /* fold escaped nl if in table */
		{
		s++;
		len -= s - p;
		continue;
		}
	break;
	}

return(p);
}

# define BACKMAX 500

char backup[BACKMAX];
char *backp = backup;

void
un1getc(int c)
{
if (c=='\n')
	iline--;
*backp++ = c;
if (backp >= backup+BACKMAX)
	error(gettext("too much backup"));
}

int
get1char(void)
{
int c;
if (backp>backup)
	c = *--backp;
else
	c=getc(tabin);
if (c== EOF) /* EOF */
	{
	if (swapin() ==0)
		error(gettext("unexpected EOF"));
	c = getc(tabin);
	}
if (c== '\n')
	iline++;
return(c);
}
