/*
 * Copyright 1998 Sun Microsystems, Inc.  All rights reserved.
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

 /* t1.c: main control and input switching */
#
#include <locale.h>
# include "t..c"
#include <signal.h>
#include <stdlib.h>

# ifdef gcos
/* required by GCOS because file is passed to "tbl" by troff preprocessor */
# define _f1 _f
extern FILE *_f[];
# endif

# ifdef unix
# define MACROS "/usr/doctools/tmac/tmac.s"
# define MACROSS "/usr/share/lib/tmac/s"
# define PYMACS "/usr/doctools/tmac/tmac.m"
# define PYMACSS "/usr/share/lib/tmac/m"
# define MEMACSS "/usr/share/lib/tmac/e"
# endif

# ifdef gcos
# define MACROS "cc/troff/smac"
# define PYMACS "cc/troff/mmac"
# endif

# define ever (;;)

void	setinp(int, char **);

int
main(int argc, char **argv)
{
# ifdef unix
void badsig();
# endif
	(void) setlocale(LC_ALL, "");
#if !defined(TEXT_DOMAIN)
#define TEXT_DOMAIN "SYS_TEST"
#endif
	(void) textdomain(TEXT_DOMAIN);
# ifdef unix
signal(SIGPIPE, badsig);
# endif
# ifdef gcos
if(!intss()) tabout = fopen("qq", "w"); /* default media code is type 5 */
# endif
exit(tbl(argc,argv));
}

int
tbl(int argc, char **argv)
{
char line[BIGBUF];
/* required by GCOS because "stdout" is set by troff preprocessor */
tabin=stdin; tabout=stdout;
setinp(argc,argv);
while (gets1(line, sizeof line))
	{
	fprintf(tabout, "%s\n",line);
	if (prefix(".TS", line))
		tableput();
	}
fclose(tabin);
return(0);
}

int sargc;
char **sargv;

void
setinp(int argc, char **argv)
{
	sargc = argc;
	sargv = argv;
	sargc--; sargv++;
	if (sargc>0)
		swapin();
}

int
swapin(void)
{
	while (sargc>0 && **sargv=='-') /* Mem fault if no test on sargc */
		{
		if (sargc<=0) return(0);
		if (match("-me", *sargv))
			{
			*sargv = MEMACSS;
			break;
			}
		if (match("-ms", *sargv))
			{
			*sargv = MACROSS;
			break;
			}
		if (match("-mm", *sargv))
			{
			*sargv = PYMACSS;
			break;
			}
		if (match("-TX", *sargv))
			pr1403=1;
		else {
			(void) fprintf(stderr, gettext("tbl: Invalid option "
			    "(%s).\n"), *sargv);
			(void) fprintf(stderr, gettext("Usage: tbl [ -me ] "
			    "[ -mm ] [ -ms ] [ filename ] ...\n"));
			exit(1);
		}
		sargc--; sargv++;
		}
	if (sargc<=0) return(0);
# ifdef unix
/* file closing is done by GCOS troff preprocessor */
	if (tabin!=stdin) fclose(tabin);
# endif
	tabin = fopen(ifile= *sargv, "r");
	iline=1;
# ifdef unix
/* file names are all put into f. by the GCOS troff preprocessor */
	fprintf(tabout, ".ds f. %s\n",ifile);
# endif
	if (tabin==NULL)
		error(gettext("Can't open file"));
	sargc--;
	sargv++;
	return(1);
}

# ifdef unix
void
badsig(void)
{
signal(SIGPIPE, SIG_IGN);
 exit(0);
}
# endif
