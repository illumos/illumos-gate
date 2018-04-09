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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * escmain.c -- main routine for esc, the eversholt compiler
 *
 * argument processing and the general flow through all the other
 * modules is driven by this file.
 */

#include <stdio.h>
#include <string.h>
#ifdef sun
#include <stdlib.h>
#else
#include <getopt.h>
#endif /* sun */
#include "out.h"
#include "stats.h"
#include "alloc.h"
#include "stable.h"
#include "literals.h"
#include "lut.h"
#include "esclex.h"
#include "eftwrite.h"
#include "ptree.h"
#include "tree.h"
#include "check.h"
#include "version.h"

/* stuff exported by yacc-generated parsers */
extern void yyparse(void);
extern int yydebug;

/*
 * This external definition has to be here.  If we put it in literals.h
 * lint complains about the declaration not being used within the block
 * when compiling literals.c.
 */
extern void literals_init(void);

static const char *Usage =
"[-SYdghpqvy] [-Dname[=def]] [-I dir] [-Uname] [-o outfile] esc-files...";
static const char *Help =
"\tinput files are run through cpp and concatenated.\n"
"\t-D name[=def] Pass to cpp\n"
"\t-I dir        Pass to cpp\n"
"\t-S            Print stats for compiler memory usage, etc.\n"
"\t-U name       Pass to cpp\n"
"\t-Y            Enable parser debug output\n"
"\t-d            Enable general debug output\n"
"\t-g            Print generated iterators (use with -p)\n"
"\t-h            Print this help message\n"
"\t-o outfile    Emit compiled EFT to \"outfile\"\n"
"\t-p            Print complete parse tree\n"
"\t-q            Quiet mode: suppress warnings\n"
"\t-v            Enable verbose output\n"
"\t-y            Enable lexer debug output";

int Debug;
int Verbose;
int Warn = 1;	/* the esc compiler should issue language warnings */

extern int Pchildgen;	/* flag to ptree for printing generated iterators */

#define	MAXARGS 8192
char Args[MAXARGS];

#define	MAXCPPARGS 4000
static char Cppargs[MAXCPPARGS];

int
main(int argc, char *argv[])
{
	char flagbuf[] = " -D";
	char **av;
	int c;
	int stats = 0;
	int lexecho = 0;
	const char *outfile = NULL;
	int count;
	int i;
	int pflag = 0;

	alloc_init();
	out_init(argv[0]);
	stats_init(1);		/* extended stats always enabled for esc */
	stable_init(0);
	literals_init();
	lut_init();
	tree_init();
	eftwrite_init();

	/* built a best effort summary of args for eftwrite() */
	count = 0;
	for (i = 1; i < argc; i++) {
		char *ptr = argv[i];

		if (count < MAXARGS - 1)
			Args[count++] = ' ';

		while (count < MAXARGS - 1 && *ptr)
			Args[count++] = *ptr++;

	}
	Args[count] = '\0';



	while ((c = getopt(argc, argv, "D:I:SU:Ydgho:pqvy")) != EOF) {
		switch (c) {
		case 'D':
		case 'I':
		case 'U':
			if (strlen(optarg) + strlen(Cppargs) + 4 >= MAXCPPARGS)
				out(O_DIE, "cpp args too long (max %d bytes)",
				    MAXCPPARGS);
			flagbuf[2] = c;
			(void) strcat(Cppargs, flagbuf);
			(void) strcat(Cppargs, optarg);
			break;

		case 'S':
			stats++;
			break;

		case 'Y':
			yydebug++;
			break;

		case 'd':
			Debug++;
			break;

		case 'g':
			Pchildgen++;
			break;

		case 'h':
		case '?':
			out(O_PROG, "eversholt compiler version %d.%d",
			    VERSION_MAJOR, VERSION_MINOR);
			out(O_DIE|O_USAGE, "%s\n%s", Usage, Help);
			/*NOTREACHED*/
			break;

		case 'o':
			outfile = optarg;
			break;

		case 'p':
			pflag++;
			break;

		case 'q':
			Warn = 0;
			break;

		case 'v':
			Verbose++;
			break;

		case 'y':
			lexecho++;
			break;

		default:
			out(O_DIE|O_USAGE, Usage);
			/*NOTREACHED*/
		}
	}

	out(O_PROG|O_VERB, "eversholt compiler version %d.%d",
	    VERSION_MAJOR, VERSION_MINOR);

	argc -= optind;
	av = &argv[optind];

	if (argc < 1) {
		out(O_ERR, "no esc source files given");
		out(O_DIE|O_USAGE, Usage);
		/*NOTREACHED*/
	}

	lex_init(av, Cppargs, lexecho);
	check_init();
	yyparse();
	(void) lex_fini();

	tree_report();

	if (count = out_errcount())
		out(O_DIE, "%d language error%s encountered, exiting.",
		    OUTS(count));

	if (outfile)
		eftwrite(outfile);

	if (pflag)
		ptree_name_iter(O_OK, tree_root(NULL));

	if (stats) {
		out(O_OK, "Stats:");
		stats_publish();
	}

	out_exit(0);
	/*NOTREACHED*/
	return (0);
}
