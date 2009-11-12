/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */

/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

#include <stdio.h>
#include <ctype.h>
#include <signal.h>
#include <locale.h>
#include <libintl.h>
#include <stdarg.h>
#include <errno.h>
#include <values.h>
#include <langinfo.h>
#include "awk.h"
#include "y.tab.h"

char	*version = "version Oct 11, 1989";

int	dbg	= 0;
uchar	*cmdname;	/* gets argv[0] for error messages */
uchar	*lexprog;	/* points to program argument if it exists */
int	compile_time = 2;	/* for error printing: */
				/* 2 = cmdline, 1 = compile, 0 = running */
char	radixpoint = '.';

static uchar	**pfile = NULL;	/* program filenames from -f's */
static int	npfile = 0;	/* number of filenames */
static int	curpfile = 0;	/* current filename */

int
main(int argc, char *argv[], char *envp[])
{
	uchar *fs = NULL;
	char	*nl_radix;
	/*
	 * At this point, numbers are still scanned as in
	 * the POSIX locale.
	 * (POSIX.2, volume 2, P867, L4742-4757)
	 */
	(void) setlocale(LC_ALL, "");
	(void) setlocale(LC_NUMERIC, "C");
#if !defined(TEXT_DOMAIN)	/* Should be defined by cc -D */
#define	TEXT_DOMAIN	"SYS_TEST"	/* Use this only if it weren't */
#endif
	(void) textdomain(TEXT_DOMAIN);
	cmdname = (uchar *)argv[0];
	if (argc == 1) {
		(void) fprintf(stderr, gettext(
		    "Usage: %s [-f programfile | 'program'] [-Ffieldsep] "
		    "[-v var=value] [files]\n"), cmdname);
		exit(1);
	}
	(void) signal(SIGFPE, fpecatch);
	yyin = NULL;
	syminit();
	while (argc > 1 && argv[1][0] == '-' && argv[1][1] != '\0') {
		if (strcmp(argv[1], "--") == 0) {
			/* explicit end of args */
			argc--;
			argv++;
			break;
		}
		switch (argv[1][1]) {
		case 'f':	/* next argument is program filename */
			argc--;
			argv++;
			if (argc <= 1)
				ERROR "no program filename" FATAL;
			pfile = realloc(pfile, sizeof (uchar *) * (npfile + 1));
			if (pfile == NULL)
				ERROR "out of space in main" FATAL;
			pfile[npfile++] = (uchar *)argv[1];
			break;
		case 'F':	/* set field separator */
			if (argv[1][2] != 0) {	/* arg is -Fsomething */
				/* wart: t=>\t */
				if (argv[1][2] == 't' && argv[1][3] == 0)
					fs = (uchar *) "\t";
				else if (argv[1][2] != 0)
					fs = (uchar *)&argv[1][2];
			} else {		/* arg is -F something */
				argc--; argv++;
				if (argc > 1) {
					/* wart: t=>\t */
					if (argv[1][0] == 't' &&
					    argv[1][1] == 0)
						fs = (uchar *) "\t";
					else if (argv[1][0] != 0)
						fs = (uchar *)&argv[1][0];
				}
			}
			if (fs == NULL || *fs == '\0')
				ERROR "field separator FS is empty" WARNING;
			break;
		case 'v':	/* -v a=1 to be done NOW.  one -v for each */
			if (argv[1][2] == '\0' && --argc > 1 &&
			    isclvar((uchar *)(++argv)[1]))
				setclvar((uchar *)argv[1]);
			break;
		case 'd':
			dbg = atoi(&argv[1][2]);
			if (dbg == 0)
				dbg = 1;
			(void) printf("awk %s\n", version);
			break;
		default:
			ERROR "unknown option %s ignored", argv[1] WARNING;
			break;
		}
		argc--;
		argv++;
	}
	/* argv[1] is now the first argument */
	if (npfile == 0) {	/* no -f; first argument is program */
		if (argc <= 1)
			ERROR "no program given" FATAL;
		dprintf(("program = |%s|\n", argv[1]));
		lexprog = (uchar *)argv[1];
		argc--;
		argv++;
	}
	compile_time = 1;
	argv[0] = (char *)cmdname;	/* put prog name at front of arglist */
	dprintf(("argc=%d, argv[0]=%s\n", argc, argv[0]));
	arginit(argc, (uchar **)argv);
	envinit((uchar **)envp);
	(void) yyparse();
	if (fs)
		*FS = qstring(fs, '\0');
	dprintf(("errorflag=%d\n", errorflag));
	/*
	 * done parsing, so now activate the LC_NUMERIC
	 */
	(void) setlocale(LC_ALL, "");
	nl_radix = nl_langinfo(RADIXCHAR);
	if (nl_radix)
		radixpoint = *nl_radix;

	if (errorflag == 0) {
		compile_time = 0;
		run(winner);
	} else
		bracecheck();
	return (errorflag);
}

int
pgetc(void)		/* get program character */
{
	int c;

	for (;;) {
		if (yyin == NULL) {
			if (curpfile >= npfile)
				return (EOF);
			yyin = (strcmp((char *)pfile[curpfile], "-") == 0) ?
			    stdin : fopen((char *)pfile[curpfile], "r");
			if (yyin == NULL) {
				ERROR "can't open file %s",
				    pfile[curpfile] FATAL;
			}
		}
		if ((c = getc(yyin)) != EOF)
			return (c);
		(void) fclose(yyin);
		yyin = NULL;
		curpfile++;
	}
}
