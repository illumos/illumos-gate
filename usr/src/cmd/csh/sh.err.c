/*
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * Copyright (c) 1980 Regents of the University of California.
 * All rights reserved.  The Berkeley Software License Agreement
 * specifies the terms and conditions for redistribution.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "sh.h"
#include <locale.h>
#include <dirent.h>
#include <string.h>
/*
 * #include <sys/ioctl.h>
 * #include <stdlib.h>
 */
#include "sh.tconst.h"
/*
 * C Shell
 */


bool	errspl;			/* Argument to error was spliced by seterr2 */
tchar one[2] = { '1', 0 };
tchar *onev[2] = { one, NOSTR };
/* 
 *    contains DIR * for last opendir_(), its left open if an error
 *    longjmp (reset) occurs before it gets closed via closedir.
 *    if its not null in the error handler, then closedir it.
 */
DIR *Dirp = NULL;

/*
 * Print error string s with optional argument arg.
 * This routine always resets or exits.  The flag haderr
 * is set so the routine who catches the unwind can propogate
 * it if they want.
 *
 * Note that any open files at the point of error will eventually
 * be closed in the routine process in sh.c which is the only
 * place error unwinds are ever caught.
 */
/*VARARGS1*/
void
error(s, a1, a2)
     char	*s;
{
	tchar **v;
	char *ep;

	/*
	 * Must flush before we print as we wish output before the error
	 * to go on (some form of) standard output, while output after
	 * goes on (some form of) diagnostic output.
	 * If didfds then output will go to 1/2 else to FSHOUT/FSHDIAG.
	 * See flush in sh.print.c.
	 */
	flush();
	haderr = 1;		/* Now to diagnostic output */
	timflg = 0;		/* This isn't otherwise reset */
	if (v = pargv)
		pargv = 0, blkfree(v);
	if (v = gargv)
		gargv = 0, blkfree(v);

	/*
	 * A zero arguments causes no printing, else print
	 * an error diagnostic here.
	 */
	if (s) {
			printf(s, a1, a2), printf("\n"); 
	}
			

	didfds = 0;		/* Forget about 0,1,2 */
	if ((ep = err) && errspl) {
		errspl = 0;
		xfree(ep);
	}
	errspl = 0;

	if ( Dirp ){
		closedir(Dirp);
		Dirp = NULL;
	}

	/*
	 * Go away if -e or we are a child shell
	 */
	if (exiterr || child) {
		exit(1);
	}

	/*
	 * Reset the state of the input.
	 * This buffered seek to end of file will also
	 * clear the while/foreach stack.
	 */
	btoeof();

	setq(S_status, onev, &shvhed);
	if (tpgrp > 0)
		(void) ioctl(FSHTTY, TIOCSPGRP,  (char *)&tpgrp);
	reset();		/* Unwind */
}

/*
 * Perror is the shells version of perror which should otherwise
 * never be called.
 */
void
Perror(tchar *s)
{
	char	chbuf[BUFSIZ];

	/*
	 * Perror uses unit 2, thus if we didn't set up the fd's
	 * we must set up unit 2 now else the diagnostic will disappear
	 */
	if (!didfds) {
		int oerrno = errno;

		(void) dcopy(SHDIAG, 2);
		errno = oerrno;
	}
	tstostr(chbuf, s);
	perror(chbuf);
	error(NULL);		/* To exit or unwind */
}

void
bferr(char *cp)
{

	flush();
	haderr = 1;
	if( bname) printf("%t: ", bname);
	error("%s", gettext(cp));
}

/*
 * The parser and scanner set up errors for later by calling seterr,
 * which sets the variable err as a side effect; later to be tested,
 * e.g. in process.
 */
void
seterr(char *s)
{

	if (err == 0)
		err = s, errspl = 0;
}

/* Set err to a splice of cp and dp, to be freed later in error() */
void
seterr2(tchar *cp, char *dp)
{
	char	chbuf[BUFSIZ];
	char	*gdp;

	if (err)
		return;

	/* Concatinate cp and dp in the allocated space. */
	tstostr(chbuf, cp);
	gdp = gettext(dp);
	err = (char *)xalloc(strlen(chbuf)+strlen(gdp)+1);
	strcpy(err, chbuf);
	strcat(err, gdp);

	errspl++;/* Remember to xfree(err). */
}

/* Set err to a splice of cp with a string form of character d */
void
seterrc(char *cp, tchar d)
{
	char	chbuf[MB_LEN_MAX+1]; 

	/* don't overwrite an existing error message */
	if (err)
		return;

#ifdef MBCHAR
	{
	wchar_t	wcd=(wchar_t)(d&TRIM);
	int	i;

	i = wctomb(chbuf, wcd); /* chbuf holds d in multibyte representation. */
	chbuf[(i>0)?i:0] = (char) 0;
	}
#else
	chbuf[0]=(char)(d&TRIM); chbuf[1]=(char)0;
#endif


	/* Concatinate cp and d in the allocated space. */
	err = (char *)xalloc(strlen(cp)+strlen(chbuf)+1);
	strcpy(err, cp);
	strcat(err, chbuf);

	errspl++; /* Remember to xfree(err). */
}
