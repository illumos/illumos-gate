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

#include <stdio.h>
#include <locale.h>

extern char *comname;	/* "/usr/lib/refer/eign" */
int wholefile = 0;
int keycount = 100;
int labels = 1;
int minlen = 3;
extern int comcount;
char *iglist = "XYZ#";

extern void dofile();
extern void err();
extern char *trimnl();

int
main(int argc, char *argv[])
{
	/*
	 * this program expects as its arguments a list of
	 * files and generates a set of lines of the form
	 *	filename:byte-add,length (tab) key1 key2 key3
	 * where the byte addresses give the position within
	 * the file and the keys are the strings off the lines
	 * which are alphabetic, first six characters only.
	 */

	int i;
	char *name, qn[200];
	char *inlist = 0;

	FILE *f, *ff;

	(void) setlocale(LC_ALL, "");

#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN "SYS_TEST"
#endif
	(void) textdomain(TEXT_DOMAIN);

	while (argc > 1 && argv[1][0] == '-') {
		switch (argv[1][1]) {
		case 'c':
			comname = argv[2];
			argv++;
			argc--;
			break;
		case 'w':
			wholefile = 1;
			break;
		case 'f':
			inlist = argv[2];
			argv++;
			argc--;
			break;
		case 'i':
			iglist = argv[2];
			argv++;
			argc--;
			break;
		case 'l':
			minlen = atoi(argv[1]+2);
			if (minlen <= 0) minlen = 3;
			break;
		case 'n': /* number of common words to use */
			comcount = atoi(argv[1]+2);
			break;
		case 'k': /* number  of keys per file max */
			keycount = atoi(argv[1]+2);
			break;
		case 's': /* suppress labels, search only */
			labels = 0;
			break;
		}
		argc--;
		argv++;
	}
	if (inlist) {
		ff = fopen(inlist, "r");
		while (fgets(qn, 200, ff)) {
			trimnl(qn);
			f = fopen(qn, "r");
			if (f != NULL)
				dofile(f, qn);
			else
				fprintf(stderr, gettext("Can't read %s\n"), qn);
		}
	} else
		if (argc <= 1)
			dofile(stdin, "");
		else
			for (i = 1; i < argc; i++) {
				f = fopen(name = argv[i], "r");
				if (f == NULL)
					err(gettext("No file %s"), name);
				else
					dofile(f, name);
			}
	return (0);
}
