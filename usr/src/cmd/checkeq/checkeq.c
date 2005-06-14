/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


/*
 * Copyright (c) 1980 Regents of the University of California.
 * All rights reserved. The Berkeley software License Agreement
 * specifies the terms and conditions for redistribution.
 */

/*
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <stdlib.h>
#include <locale.h>

static void check(FILE *);

static	FILE	*fin;
static	int	delim	= '$';

int
main(int argc, char **argv)
{
	(void) setlocale(LC_ALL, "");
#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN	"SYS_TEST"
#endif
	(void) textdomain(TEXT_DOMAIN);
	if (argc <= 1)
		check(stdin);
	else
		while (--argc > 0) {
			if ((fin = fopen(*++argv, "r")) == NULL) {
				perror(*argv);
				exit(1);
			}
			(void) printf("%s:\n", *argv);
			check(fin);
			(void) fclose(fin);
		}
	return (0);
}

static void
check(FILE *f)
{
	int start, line, eq, ndel, totdel;
	char in[600], *p;

	start = eq = line = ndel = totdel = 0;
	while (fgets(in, 600, f) != NULL) {
		line++;
		ndel = 0;
		for (p = in; *p; p++)
			if (*p == delim)
				ndel++;
		if (*in == '.' && *(in+1) == 'E' && *(in+2) == 'Q') {
			if (eq++)
				(void) printf(
				    gettext("   Spurious EQ, line %d\n"),
				    line);
			if (totdel)
				(void) printf(
				    gettext("   EQ in %c%c, line %d\n"),
				    delim, delim, line);
		} else if (*in == '.' && *(in+1) == 'E' && *(in+2) == 'N') {
			if (eq == 0)
				(void) printf(
				    gettext("   Spurious EN, line %d\n"),
				    line);
			else
				eq = 0;
			if (totdel > 0)
				(void) printf(
				    gettext("   EN in %c%c, line %d\n"),
				    delim, delim, line);
			start = 0;
		} else if (eq && *in == 'd' && *(in+1) == 'e' &&
		    *(in+2) == 'l' && *(in+3) == 'i' && *(in+4) == 'm') {
			for (p = in+5; *p; p++)
				if (*p != ' ') {
					if (*p == 'o' && *(p+1) == 'f')
						delim = 0;
					else
						delim = *p;
					break;
				}
			if (delim == 0)
				(void) printf(
				    gettext("   Delim off, line %d\n"),
				    line);
			else
				(void) printf(
				    gettext("   New delims %c%c, line %d\n"),
				    delim, delim, line);
		}
		if (ndel > 0 && eq > 0)
			(void) printf(
			    gettext("   %c%c in EQ, line %d\n"), delim,
			    delim, line);
		if (ndel == 0)
			continue;
		totdel += ndel;
		if (totdel%2) {
			if (start == 0)
				start = line;
			else {
				(void) printf(
				    gettext("   %d line %c%c, lines %d-%d\n"),
				    line-start+1, delim, delim, start, line);
				start = line;
			}
		} else {
			if (start > 0) {
				(void) printf(
				    gettext("   %d line %c%c, lines %d-%d\n"),
				    line-start+1, delim, delim, start, line);
				start = 0;
			}
			totdel = 0;
		}
	}
	if (totdel)
		(void) printf(gettext("   Unfinished %c%c\n"), delim, delim);
	if (eq)
		(void) printf(gettext("   Unfinished EQ\n"));
}
