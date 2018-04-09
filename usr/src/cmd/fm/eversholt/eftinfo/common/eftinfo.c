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
 * eftinfo.c -- main routine for eftinfo command
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
#include "alloc.h"
#include "stats.h"
#include "stable.h"
#include "literals.h"
#include "lut.h"
#include "esclex.h"
#include "ptree.h"
#include "tree.h"
#include "check.h"
#include "version.h"
#include "eftread.h"

/* stuff exported by yacc-generated parsers */
extern void yyparse(void);
extern int yydebug;

/*
 * This external definition has to be here.  If we put it in literals.h
 * lint complains about the declaration not being used within the block
 * when compiling literals.c.
 */
extern void literals_init(void);

static const char *Usage = "[-DEPghpqvw] eft-files...";
static const char *Help =
"\t-D            Print dictionaries EFT references.\n"
"\t-E            Print ereports EFT will consume.\n"
"\t-P            Print problems EFT can diagnose.\n"
"\t-g            Print generated iterators (use with -p)\n"
"\t-h            Print this help message\n"
"\t-p            Print complete propagation tree\n"
"\t-q            Quiet mode, no header info printed\n"
"\t-v            Enable verbose output\n"
"\t-w            Enable language warnings";
/*
 * and some undocumented extras...
 *	"\t-S            Print stats for compiler memory usage, etc.\n"
 *	"\t-Y            Enable parser debug output\n"
 *	"\t-d            Enable general debug output\n"
 *	"\t-y            Enable lexer debug output\n"
 *
 */

int Debug;
int Verbose;
int Warn;

extern int Pchildgen;	/* flag to ptree for printing generated interators */

extern struct lut *Dicts;

/*ARGSUSED*/
static void
dictprint(const char *s, void *rhs, void *arg)
{
	static char *sep = "";

	out(O_OK|O_NONL, "%s%s", sep, s);
	sep = ":";
}

int
main(int argc, char *argv[])
{
	int c;
	int count;
	int Dflag = 0;
	int Eflag = 0;
	int yflag = 0;
	int Pflag = 0;
	int Sflag = 0;
	int pflag = 0;
	int qflag = 0;

	alloc_init();
	out_init(argv[0]);
	stats_init(1);		/* extended stats always enabled for eftinfo */
	stable_init(0);
	literals_init();
	lut_init();
	tree_init();

	while ((c = getopt(argc, argv, "DEPSYdghpqvwy")) != EOF) {
		switch (c) {
		case 'D':
			Dflag++;
			break;

		case 'E':
			Eflag++;
			break;

		case 'y':
			yflag++;
			break;

		case 'P':
			Pflag++;
			break;

		case 'S':
			Sflag++;
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
			out(O_PROG, "version %d.%d",
			    VERSION_MAJOR, VERSION_MINOR);
			out(O_DIE|O_USAGE, "%s\n%s", Usage, Help);
			/*NOTREACHED*/
			break;

		case 'p':
			pflag++;
			break;

		case 'q':
			qflag++;
			break;

		case 'v':
			Verbose++;
			break;

		case 'w':
			Warn++;
			break;

		default:
			out(O_DIE|O_USAGE, Usage);
			/*NOTREACHED*/
		}
	}

	out(O_PROG|O_VERB, "version %d.%d",
	    VERSION_MAJOR, VERSION_MINOR);
	argc -= optind;

	if (argc < 1)
		out(O_DIE|O_USAGE, Usage);

	if (!qflag)
		eftread_showheader(1);

	lex_init(&argv[optind], NULL, yflag);
	check_init();
	yyparse();
	(void) lex_fini();

	tree_report();

	if (count = out_errcount())
		out(O_DIE, "%d error%s encountered, exiting.", OUTS(count));

	if (Dflag) {
		out(O_OK|O_NONL, "Dictionaries: ");
		lut_walk(Dicts, (lut_cb)dictprint, (void *)0);
		out(O_OK, NULL);
	}

	if (Eflag)
		ptree_ereport(O_OK, NULL);

	if (Pflag) {
		ptree_fault(O_OK, NULL);
		ptree_upset(O_OK, NULL);
		ptree_defect(O_OK, NULL);
	}

	if (pflag)
		ptree_name_iter(O_OK, tree_root(NULL));

	if (Sflag) {
		out(O_OK, "Stats:");
		stats_publish();
	}

	out_exit(0);
	/*NOTREACHED*/
	return (0);
}
