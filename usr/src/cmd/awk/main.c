/*
 * Copyright (C) Lucent Technologies 1997
 * All Rights Reserved
 *
 * Permission to use, copy, modify, and distribute this software and
 * its documentation for any purpose and without fee is hereby
 * granted, provided that the above copyright notice appear in all
 * copies and that both that the copyright notice and this
 * permission notice and warranty disclaimer appear in supporting
 * documentation, and that the name Lucent Technologies or any of
 * its entities not be used in advertising or publicity pertaining
 * to distribution of the software without specific, written prior
 * permission.
 *
 * LUCENT DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE,
 * INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS.
 * IN NO EVENT SHALL LUCENT OR ANY OF ITS ENTITIES BE LIABLE FOR ANY
 * SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER
 * IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION,
 * ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF
 * THIS SOFTWARE.
 */

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

char	*version = "version Aug 27, 2018";

int	dbg	= 0;
Awkfloat	srand_seed = 1;
char	*cmdname;	/* gets argv[0] for error messages */
char	*lexprog;	/* points to program argument if it exists */
int	compile_time = 2;	/* for error printing: */
				/* 2 = cmdline, 1 = compile, 0 = running */

static char	**pfile = NULL;	/* program filenames from -f's */
static int	npfile = 0;	/* number of filenames */
static int	curpfile = 0;	/* current filename */

int	safe	= 0;	/* 1 => "safe" mode */

int
main(int argc, char *argv[], char *envp[])
{
	const char *fs = NULL;
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
	cmdname = argv[0];
	if (argc == 1) {
		(void) fprintf(stderr, gettext(
		    "Usage: %s [-f programfile | 'program'] [-Ffieldsep] "
		    "[-v var=value] [files]\n"), cmdname);
		exit(1);
	}
	(void) signal(SIGFPE, fpecatch);

	srand_seed = 1;
	srand((unsigned int)srand_seed);

	yyin = NULL;
	symtab = makesymtab(NSYMTAB/NSYMTAB);
	while (argc > 1 && argv[1][0] == '-' && argv[1][1] != '\0') {
		if (strcmp(argv[1], "-version") == 0 ||
		    strcmp(argv[1], "--version") == 0) {
			(void) printf("awk %s\n", version);
			exit(0);
			break;
		}
		if (strcmp(argv[1], "--") == 0) {
			/* explicit end of args */
			argc--;
			argv++;
			break;
		}
		switch (argv[1][1]) {
		case 's':
			if (strcmp(argv[1], "-safe") == 0)
				safe = 1;
			break;
		case 'f':	/* next argument is program filename */
			if (argv[1][2] != 0) {  /* arg is -fsomething */
				pfile = realloc(pfile,
				    sizeof (char *) * (npfile + 1));
				if (pfile == NULL)
					FATAL("out of space in main");
				pfile[npfile++] = &argv[1][2];
			} else {		/* arg is -f something */
				argc--; argv++;
				if (argc <= 1)
					FATAL("no program filename");
				pfile = realloc(pfile,
				    sizeof (char *) * (npfile + 1));
				if (pfile == NULL)
					FATAL("out of space in main");
				pfile[npfile++] = argv[1];
			}
			break;
		case 'F':	/* set field separator */
			if (argv[1][2] != 0) {	/* arg is -Fsomething */
				/* wart: t=>\t */
				if (argv[1][2] == 't' && argv[1][3] == 0)
					fs = "\t";
				else if (argv[1][2] != 0)
					fs = &argv[1][2];
			} else {		/* arg is -F something */
				argc--; argv++;
				if (argc > 1) {
					/* wart: t=>\t */
					if (argv[1][0] == 't' &&
					    argv[1][1] == 0)
						fs = "\t";
					else if (argv[1][0] != 0)
						fs = &argv[1][0];
				}
			}
			if (fs == NULL || *fs == '\0')
				WARNING("field separator FS is empty");
			break;
		case 'v':	/* -v a=1 to be done NOW.  one -v for each */
			if (argv[1][2] != 0) {  /* arg is -vsomething */
				if (isclvar(&argv[1][2]))
					setclvar(&argv[1][2]);
				else
					FATAL("invalid -v option argument: %s",
					    &argv[1][2]);
			} else {		/* arg is -v something */
				argc--; argv++;
				if (argc <= 1)
					FATAL("no variable name");
				if (isclvar(argv[1]))
					setclvar(argv[1]);
				else
					FATAL("invalid -v option argument: %s",
					    argv[1]);
			}
			break;
		case 'd':
			dbg = atoi(&argv[1][2]);
			if (dbg == 0)
				dbg = 1;
			(void) printf("awk %s\n", version);
			break;
		default:
			WARNING("unknown option %s ignored", argv[1]);
			break;
		}
		argc--;
		argv++;
	}
	/* argv[1] is now the first argument */
	if (npfile == 0) {	/* no -f; first argument is program */
		if (argc <= 1) {
			if (dbg)
				exit(0);
			FATAL("no program given");
		}
		dprintf(("program = |%s|\n", argv[1]));
		lexprog = argv[1];
		argc--;
		argv++;
	}
	recinit(recsize);
	syminit();
	compile_time = 1;
	argv[0] = cmdname;	/* put prog name at front of arglist */
	dprintf(("argc=%d, argv[0]=%s\n", argc, argv[0]));
	arginit(argc, argv);
	if (!safe)
		envinit(envp);
	(void) yyparse();
	if (fs)
		*FS = qstring(fs, '\0');
	dprintf(("errorflag=%d\n", errorflag));
	/*
	 * done parsing, so now activate the LC_NUMERIC
	 */
	(void) setlocale(LC_ALL, "");

	if (errorflag == 0) {
		compile_time = 0;
		run(winner);
	} else
		bracecheck();
	return (errorflag);
}

int
pgetc(void)		/* get 1 character from awk program */
{
	int c;

	for (;;) {
		if (yyin == NULL) {
			if (curpfile >= npfile)
				return (EOF);
			yyin = (strcmp(pfile[curpfile], "-") == 0) ?
			    stdin : fopen(pfile[curpfile], "rF");
			if (yyin == NULL) {
				FATAL("can't open file %s", pfile[curpfile]);
			}
			lineno = 1;
		}
		if ((c = getc(yyin)) != EOF)
			return (c);
		if (yyin != stdin)
			(void) fclose(yyin);
		yyin = NULL;
		curpfile++;
	}
}

char *
cursource(void)	/* current source file name */
{
	if (curpfile < npfile)
		return (pfile[curpfile]);
	else
		return (NULL);
}
