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
 * Copyright (c) 2014 Gary Mills
 *
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/* Copyright (c) 1988 AT&T */
/* All Rights Reserved */

/* Copyright 1976, Bell Telephone Laboratories, Inc. */

#include <string.h>
#include "once.h"
#include "sgs.h"
#include <locale.h>
#include <limits.h>

static wchar_t  L_INITIAL[] = {'I', 'N', 'I', 'T', 'I', 'A', 'L', 0};
static void get1core(void);
static void free1core(void);
static void get2core(void);
static void free2core(void);
static void get3core(void);
#ifdef DEBUG
static void free3core(void);
#endif

int
main(int argc, char **argv)
{
	int i;
	int c;
	char *apath = NULL;
	char *ypath;
	Boolean eoption = 0, woption = 0;

	sargv = argv;
	sargc = argc;
	(void) setlocale(LC_ALL, "");
#ifdef DEBUG
	while ((c = getopt(argc, argv, "dyctvnewVQ:Y:")) != EOF) {
#else
	while ((c = getopt(argc, argv, "ctvnewVQ:Y:")) != EOF) {
#endif
		switch (c) {
#ifdef DEBUG
			case 'd':
				debug++;
				break;
			case 'y':
				yydebug = TRUE;
				break;
#endif
			case 'V':
				(void) fprintf(stderr, "lex: %s %s\n",
				    (const char *)SGU_PKG,
				    (const char *)SGU_REL);
				break;
			case 'Q':
				v_stmp = optarg;
				if (*v_stmp != 'y' && *v_stmp != 'n')
					error(
					"lex: -Q should be followed by [y/n]");
				break;
			case 'Y':
				apath = (char *)malloc(strlen(optarg) +
				    sizeof ("/nceucform") + 1);
				if (apath == NULL)
					error("No available memory "
					    "for directory name.");
				else
					apath = strcpy(apath, optarg);
				break;
			case 'c':
				ratfor = FALSE;
				break;
			case 't':
				fout = stdout;
				break;
			case 'v':
				report = 1;
				break;
			case 'n':
				report = 0;
				break;
			case 'w':
			case 'W':
				woption = 1;
				handleeuc = 1;
				widecio = 1;
				break;
			case 'e':
			case 'E':
				eoption = 1;
				handleeuc = 1;
				widecio = 0;
				break;
			default:
				(void) fprintf(stderr,
				"Usage: lex [-ewctvnV] [-Y directory] "
				"[-Q(y/n)] [file]\n");
				exit(1);
		}
	}
	if (woption && eoption) {
		error(
		"You may not specify both -w and -e simultaneously.");
	}
	no_input = argc - optind;
	if (no_input) {
		/* XCU4: recognize "-" file operand for stdin */
		if (strcmp(argv[optind], "-") == 0)
			fin = stdin;
		else {
			fin = fopen(argv[optind], "r");
			if (fin == NULL)
				error(
				"Can't open input file -- %s", argv[optind]);
		}
	} else
		fin = stdin;

	/* may be gotten: def, subs, sname, schar, ccl, dchar */
	(void) gch();

	/* may be gotten: name, left, right, nullstr, parent */
	get1core();

	scopy(L_INITIAL, sp);
	sname[0] = sp;
	sp += slength(L_INITIAL) + 1;
	sname[1] = 0;

	/* XCU4: %x exclusive start */
	exclusive[0] = 0;

	if (!handleeuc) {
		/*
		 * Set ZCH and ncg to their default values
		 * as they may be needed to handle %t directive.
		 */
		ZCH = ncg = NCH; /* ncg behaves as constant in this mode. */
	}

	/* may be disposed of: def, subs, dchar */
	if (yyparse())
		exit(1);	/* error return code */

	if (handleeuc) {
		ncg = ncgidtbl * 2;
		ZCH = ncg;
		if (ncg >= MAXNCG)
			error(
			"Too complex rules -- requires too many char groups.");
		sortcgidtbl();
	}
	repbycgid(); /* Call this even in ASCII compat. mode. */

	/*
	 * maybe get:
	 *		tmpstat, foll, positions, gotof, nexts,
	 *		nchar, state, atable, sfall, cpackflg
	 */
	free1core();
	get2core();
	ptail();
	mkmatch();
#ifdef DEBUG
	if (debug)
		pccl();
#endif
	sect  = ENDSECTION;
	if (tptr > 0)
		cfoll(tptr-1);
#ifdef DEBUG
	if (debug)
		pfoll();
#endif
	cgoto();
#ifdef DEBUG
	if (debug) {
		(void) printf("Print %d states:\n", stnum + 1);
		for (i = 0; i <= stnum; i++)
			stprt(i);
	}
#endif
	/*
	 * may be disposed of:
	 *		positions, tmpstat, foll, state, name,
	 *		left, right, parent, ccl, schar, sname
	 * maybe get:	 verify, advance, stoff
	 */
	free2core();
	get3core();
	layout();
	/*
	 * may be disposed of:
	 *		verify, advance, stoff, nexts, nchar,
	 *		gotof, atable, ccpackflg, sfall
	 */

#ifdef DEBUG
	free3core();
#endif

	if (handleeuc) {
		if (ratfor)
			error("Ratfor is not supported by -w or -e option.");
		ypath = EUCNAME;
	}
	else
		ypath = ratfor ? RATNAME : CNAME;

	if (apath != NULL)
		ypath = strcat(apath, strrchr(ypath, '/'));
	fother = fopen(ypath, "r");
	if (fother == NULL)
		error("Lex driver missing, file %s", ypath);
	while ((i = getc(fother)) != EOF)
		(void) putc((char)i, fout);
	(void) fclose(fother);
	(void) fclose(fout);
	free(apath);
	if (report == 1)
		statistics();
	(void) fclose(stdout);
	(void) fclose(stderr);
	return (0);	/* success return code */
}

static void
get1core(void)
{
	/*LINTED: E_BAD_PTR_CAST_ALIGN*/
	ccptr =	ccl = (CHR *)myalloc(CCLSIZE, sizeof (*ccl));
	/*LINTED: E_BAD_PTR_CAST_ALIGN*/
	pcptr = pchar = (CHR *)myalloc(pchlen, sizeof (*pchar));
	/*LINTED: E_BAD_PTR_CAST_ALIGN*/
	def = (CHR **)myalloc(DEFSIZE, sizeof (*def));
	/*LINTED: E_BAD_PTR_CAST_ALIGN*/
	subs = (CHR **)myalloc(DEFSIZE, sizeof (*subs));
	/*LINTED: E_BAD_PTR_CAST_ALIGN*/
	dp = dchar = (CHR *)myalloc(DEFCHAR, sizeof (*dchar));
	/*LINTED: E_BAD_PTR_CAST_ALIGN*/
	sname = (CHR **)myalloc(STARTSIZE, sizeof (*sname));
	/* XCU4: exclusive start array */
	/*LINTED: E_BAD_PTR_CAST_ALIGN*/
	exclusive = (int *)myalloc(STARTSIZE, sizeof (*exclusive));
	/*LINTED: E_BAD_PTR_CAST_ALIGN*/
	sp = schar = (CHR *)myalloc(STARTCHAR, sizeof (*schar));
	if (ccl == 0 || def == 0 ||
	    pchar == 0 || subs == 0 || dchar == 0 ||
	    sname == 0 || exclusive == 0 || schar == 0)
		error("Too little core to begin");
}

static void
free1core(void)
{
	free(def);
	free(subs);
	free(dchar);
}

static void
get2core(void)
{
	int i;
	/*LINTED: E_BAD_PTR_CAST_ALIGN*/
	gotof = (int *)myalloc(nstates, sizeof (*gotof));
	/*LINTED: E_BAD_PTR_CAST_ALIGN*/
	nexts = (int *)myalloc(ntrans, sizeof (*nexts));
	/*LINTED: E_BAD_PTR_CAST_ALIGN*/
	nchar = (CHR *)myalloc(ntrans, sizeof (*nchar));
	/*LINTED: E_BAD_PTR_CAST_ALIGN*/
	state = (int **)myalloc(nstates, sizeof (*state));
	/*LINTED: E_BAD_PTR_CAST_ALIGN*/
	atable = (int *)myalloc(nstates, sizeof (*atable));
	/*LINTED: E_BAD_PTR_CAST_ALIGN*/
	sfall = (int *)myalloc(nstates, sizeof (*sfall));
	cpackflg = (Boolean *)myalloc(nstates, sizeof (*cpackflg));
	/*LINTED: E_BAD_PTR_CAST_ALIGN*/
	tmpstat = (CHR *)myalloc(tptr+1, sizeof (*tmpstat));
	/*LINTED: E_BAD_PTR_CAST_ALIGN*/
	foll = (int **)myalloc(tptr+1, sizeof (*foll));
	/*LINTED: E_BAD_PTR_CAST_ALIGN*/
	nxtpos = positions = (int *)myalloc(maxpos, sizeof (*positions));
	if (tmpstat == 0 || foll == 0 || positions == 0 ||
	    gotof == 0 || nexts == 0 || nchar == 0 ||
	    state == 0 || atable == 0 || sfall == 0 || cpackflg == 0)
		error("Too little core for state generation");
	for (i = 0; i <= tptr; i++)
		foll[i] = 0;
}

static void
free2core(void)
{
	free(positions);
	free(tmpstat);
	free(foll);
	free(name);
	free(left);
	free(right);
	free(parent);
	free(nullstr);
	free(state);
	free(sname);
	/* XCU4: exclusive start array */
	free(exclusive);
	free(schar);
	free(ccl);
}

static void
get3core(void)
{
	/*LINTED: E_BAD_PTR_CAST_ALIGN*/
	verify = (int *)myalloc(outsize, sizeof (*verify));
	/*LINTED: E_BAD_PTR_CAST_ALIGN*/
	advance = (int *)myalloc(outsize, sizeof (*advance));
	/*LINTED: E_BAD_PTR_CAST_ALIGN*/
	stoff = (int *)myalloc(stnum+2, sizeof (*stoff));
	if (verify == 0 || advance == 0 || stoff == 0)
		error("Too little core for final packing");
}

#ifdef DEBUG
static void
free3core(void)
{
	free(advance);
	free(verify);
	free(stoff);
	free(gotof);
	free(nexts);
	free(nchar);
	free(atable);
	free(sfall);
	free(cpackflg);
}
#endif

BYTE *
myalloc(int a, int b)
{
	BYTE *i;
	i = calloc(a,  b);
	if (i == 0)
		warning("calloc returns a 0");
	return (i);
}

void
yyerror(char *s)
{
	(void) fprintf(stderr,
	    "\"%s\":line %d: Error: %s\n", sargv[optind], yyline, s);
}
