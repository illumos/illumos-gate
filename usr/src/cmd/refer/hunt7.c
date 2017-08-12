/*
 * Copyright 2017 Gary Mills
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

#include <stdio.h>
#include <locale.h>
#include <assert.h>
#define	SAME 0
#define	FGCT 10
#define	FGSIZE 150

int keepold = 1;	/* keep old things for fgrep search */
char fgspace[FGSIZE];
char *fgp = fgspace;
char *fgnames[FGCT];
char **fgnamp = fgnames;

extern char *mindex();

long
findline(char *in, char **out, int outlen, long indexdate)
{
	static char name[100] = "";
	char *p, **ftp;
	extern long gdate();
	static FILE *fa = NULL;
	long lp, llen;
	int k, nofil;

	if (mindex(in, '!'))
		return (0);

	nofil = in[0] == 0;
	for (p = in; *p && *p != ':' && *p != ';'; p++)
		;
	if (*p) *p++ = 0;
	else p = in;
	k = sscanf(p, "%ld,%ld", &lp, &llen);
	if (k < 2) {
		lp = 0;
		llen = outlen;
	}
	if (nofil) {
		fa = stdin;
	} else
		if (strcmp(name, in) != 0 || 1) {
			if (fa != NULL)
				fa = freopen(in, "r", fa);
			else
				fa = fopen(in, "r");
			if (fa == NULL)
				return (0);
			/* err("Can't open %s", in); */
			strcpy(name, in);
			if (gdate(fa) > indexdate && indexdate != 0) {
				if (keepold) {
					for (ftp = fgnames; ftp < fgnamp; ftp++)
						if (strcmp(*ftp, name) == SAME)
							return (0);
					strcpy(*fgnamp++ = fgp, name);
					assert(fgnamp < fgnames+FGCT);
					while (*fgp && *fgp != ':')
						fgp++;
					*fgp++ = 0;
					assert(fgp < fgspace+FGSIZE);
					return (0);
				}
				fprintf(stderr, gettext(
				    "Warning: index predates file '%s'\n"),
				    name);
			}
		}
	if (fa != NULL) {
		fseek(fa, lp, 0);
		*out = (char *)malloc(llen + 1);
		if (*out == NULL) {
			return (0);
		}
		(void) fread(*out, 1, llen, fa);
		*(*out + llen) = 0;
	}
	return (llen);
}
