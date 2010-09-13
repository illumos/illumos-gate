/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Awk -- data definitions
 *
 * Copyright (c) 1995 by Sun Microsystems, Inc.
 *
 * Copyright 1986, 1992 by Mortice Kern Systems Inc.  All rights reserved.
 *
 * Based on MKS awk(1) ported to be /usr/xpg4/bin/awk with POSIX/XCU4 changes
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "awk.h"
#include "y.tab.h"

/*
 * This file contains data definitions for awk.
 */

RESERVED	reserved[] = {
	s_BEGIN, KEYWORD, BEGIN, NULL,
	s_END, KEYWORD, END, NULL,
	M_MB_L("break"), KEYWORD, BREAK, NULL,
	M_MB_L("continue"), KEYWORD, CONTINUE, NULL,
	M_MB_L("for"), KEYWORD, FOR, NULL,
	M_MB_L("if"), KEYWORD, IF, NULL,
	M_MB_L("else"), KEYWORD, ELSE, NULL,
	M_MB_L("in"), KEYWORD, IN, NULL,
	s_next, KEYWORD, NEXT, NULL,
	M_MB_L("while"), KEYWORD, WHILE, NULL,
	M_MB_L("do"), KEYWORD, DO, NULL,
	M_MB_L("print"), KEYWORD, PRINT, NULL,
	M_MB_L("printf"), KEYWORD, PRINTF, NULL,
	M_MB_L("return"), KEYWORD, RETURN, NULL,
	M_MB_L("func"), KEYWORD, DEFFUNC, NULL,
	M_MB_L("function"), KEYWORD, DEFFUNC, NULL,
	M_MB_L("delete"), KEYWORD, DELETE, NULL,
	M_MB_L("exit"), KEYWORD, EXIT, NULL,
	s_FILENAME, VAR, 0, _null,
	s_NF, SVAR, 0, NULL,
	s_NR, VAR, 0, NULL,
	s_FS, SVAR, 1, M_MB_L(" "),
	s_OFS, VAR, 1, M_MB_L(" "),
	s_ORS, VAR, 1, M_MB_L("\n"),
	s_OFMT, VAR, 4, M_MB_L("%.6g"),
	s_CONVFMT, VAR, 4, M_MB_L("%.6g"),
	s_RS, SVAR, 1, M_MB_L("\n"),
	s_FNR, VAR, 0, NULL,
	s_SUBSEP, VAR, 1,
#ifdef	M_AWK_SUBSEP
	M_AWK_SUBSEP,
#else
	M_MB_L("\34"),
#endif
	s_ARGC, SVAR, 0, NULL,
	(LOCCHARP)NULL
};

RESFUNC	resfuncs[] = {
	s_exp, FUNC, f_exp,
	s_getline, GETLINE, f_getline,
	s_index, FUNC, f_index,
	s_int, FUNC, f_int,
	s_length, FUNC, f_length,
	s_log, FUNC, f_log,
	s_split, FUNC, f_split,
	s_sprintf, FUNC, f_sprintf,
	s_sqrt, FUNC, f_sqrt,
	s_substr, FUNC, f_substr,
	s_rand, FUNC, f_rand,
	s_srand, FUNC, f_srand,
	s_sin, FUNC, f_sin,
	s_cos, FUNC, f_cos,
	s_atan2, FUNC, f_atan2,
	s_sub, FUNC, f_sub,
	s_gsub, FUNC, f_gsub,
	s_match, FUNC, f_match,
	s_system, FUNC, f_system,
	s_ord, FUNC, f_ord,
	s_toupper, FUNC, f_toupper,
	s_tolower, FUNC, f_tolower,
	s_asort, FUNC, f_asort,
	s_close, FUNC, f_close,
	(LOCCHARP)NULL
};


OFILE	*ofiles;			/* Remembered open files (print) */
long	NIOSTREAM = 512;		/* max num of open file descriptors */




wchar_t	_null[] = M_MB_L("");		/* Empty string */
char	r[] = "r";			/* Read file mode */
char	w[] = "w";			/* Write file mode */
wchar_t	s_OFMT[] = M_MB_L("OFMT");	/* Name of "OFMT" variable */
wchar_t	s_CONVFMT[] = M_MB_L("CONVFMT"); /* Name of "CONVFMT" variable */
wchar_t	s_NR[] = M_MB_L("NR");		/* Name of "NR" variable */
wchar_t	s_NF[] = M_MB_L("NF");		/* Name of "NF" variable */
wchar_t	s_OFS[] = M_MB_L("OFS");	/* Name of "OFS" variable */
wchar_t	s_ORS[] = M_MB_L("ORS");	/* Name of "ORS" variable */
wchar_t	s_RS[] = M_MB_L("RS");		/* Name of "RS" variable */
wchar_t	s_FS[] = M_MB_L("FS");		/* Name of "FS" variable */
wchar_t	s_FNR[] = M_MB_L("FNR");	/* Name of "FNR" variable */
wchar_t	s_SUBSEP[] = M_MB_L("SUBSEP");	/* Name of "SUBSEP" variable */
wchar_t	s_ARGC[] = M_MB_L("ARGC");	/* Name of "ARGC" variable */
wchar_t	s_ARGV[] = M_MB_L("ARGV");	/* Name of "ARGV" array variable */
wchar_t	s_ENVIRON[] = M_MB_L("ENVIRON"); /* Name of "ENVIRON" array variable */
wchar_t	s_FILENAME[] = M_MB_L("FILENAME"); /* Name of "FILENAME" variable */
wchar_t	s_SYMTAB[] = M_MB_L("SYMTAB");	/* Name of "SYMTAB" variable */
wchar_t	s_BEGIN[] = M_MB_L("BEGIN");	/* Name of "BEGIN" action */
wchar_t	s_END[] = M_MB_L("END");	/* Name of "END" action */
wchar_t	s_next[] = M_MB_L("next");	/* Name of "next" keyword */
wchar_t	s_exp[] = M_MB_L("exp");	/* Name of "exp" function */
wchar_t	s_getline[] = M_MB_L("getline"); /* Name of "getline" function */
wchar_t	s_index[] = M_MB_L("index");	/* Name of "index" function */
wchar_t	s_int[] = M_MB_L("int");	/* Name of "int" function */
wchar_t	s_length[] = M_MB_L("length");	/* Name of "length" function */
wchar_t	s_log[] = M_MB_L("log");	/* Name of "log" function */
wchar_t	s_split[] = M_MB_L("split");	/* Name of "split" function */
wchar_t	s_sprintf[] = M_MB_L("sprintf"); /* Name of "sprintf" function */
wchar_t	s_sqrt[] = M_MB_L("sqrt");	/* Name of "sqrt" function */
wchar_t	s_substr[] = M_MB_L("substr");	/* Name of "substr" function */
wchar_t	s_rand[] = M_MB_L("rand");	/* Name of "rand" function */
wchar_t	s_srand[] = M_MB_L("srand");	/* Name of "srand" function */
wchar_t	s_sin[] = M_MB_L("sin");	/* Name of "sin" function */
wchar_t	s_cos[] = M_MB_L("cos");	/* Name of "cos" function */
wchar_t	s_atan2[] = M_MB_L("atan2");	/* Name of "atan" function */
wchar_t	s_sub[] = M_MB_L("sub");	/* Name of "sub" function */
wchar_t	s_gsub[] = M_MB_L("gsub");	/* Name of "gsub" function */
wchar_t	s_match[] = M_MB_L("match");	/* Name of "match" function */
wchar_t	s_system[] = M_MB_L("system");	/* Name of "system" function */
wchar_t	s_ord[] = M_MB_L("ord");	/* Name of "ord" function */
wchar_t	s_toupper[] = M_MB_L("toupper"); /* Name of "toupper" function */
wchar_t	s_tolower[] = M_MB_L("tolower"); /* Name of "tolower" function */
wchar_t	s_asort[] = M_MB_L("asort");	/* Name of "asort" function */
wchar_t	s_close[] = M_MB_L("close");	/* Name of "close" function */

wchar_t redelim;			/* Delimiter for regexp (yylex) */
uchar_t	inprint;			/* Special meaning for '>' & '|' */
uchar_t	funparm;			/* Defining function parameters */
uchar_t	splitdone;			/* Line split into fields (fieldbuf) */
uint	npattern;			/* Number of non-BEGIN patterns */
uint	nfield;				/* Number of fields (if splitdone) */
uint	fcount;				/* Field counter (used by blackfield)*/
uint	phase;				/* BEGIN, END, or 0 */
uint	running = 0;			/* Set if not in compile phase */
uchar_t	catterm;			/* Can inject concat or ';' */
uint	lexlast = '\n';			/* Last lexical token */
uint	lineno = 0;			/* Current programme line number */
uchar_t	doing_begin;			/* set if compiling BEGIN block */
uchar_t	begin_getline;			/* flags a getline was done in BEGIN */
uchar_t	needsplit;			/* Set if $0 must be split when read */
uchar_t	needenviron;			/* Set if ENVIRON variable referenced */
ushort	slevel;				/* Scope level (0 == root) */
ushort	loopexit;			/* Short circuit loop with keyword */
wchar_t	radixpoint;			/* soft radix point for I18N */
REGEXP	resep;				/* Field separator as regexp */
wchar_t	*linebuf = NULL;		/* $0 buffer - malloc'd in awk1.c */
size_t	lbuflen;			/* Length of linebuf */

/*
 * XXX - Make sure to check where this error message is printed
 */
char	interr[] = "internal execution tree error at E string";
char	nomem[] =  "insufficient memory for string storage";
NODE	*symtab[NBUCKET];		/* Heads of symbol table buckets */
NODE	*yytree;			/* Code tree */
NODE	*freelist;			/* Free every pattern {action} line */
wchar_t	*(*awkrecord) ANSI((wchar_t *, int, FILE*)) = defrecord;
					/* Function to read a record */
wchar_t	*(*awkfield) ANSI((wchar_t **)) = whitefield;
					/* Function to extract a field */

/*
 * Nodes used to speed up the execution of the
 * interpreter.
 */
NODE	*constant;			/* Node to hold a constant INT */
NODE	*const0;			/* Constant INT 0 node */
NODE	*const1;			/* Constant INT 1 node */
NODE	*constundef;			/* Undefined variable */
NODE	*field0;			/* $0 */
NODE	*incNR;				/* Code to increment NR variable */
NODE	*incFNR;			/* Code to increment FNR variable */
NODE	*clrFNR;			/* Zero FNR variable (each file) */
NODE	*ARGVsubi;			/* Compute ARGV[i] */
NODE	*varNR;				/* Remove search for NR variable */
NODE	*varFNR;			/* Don't search for FNR variable */
NODE	*varNF;				/* Pointer to NF variable */
NODE	*varOFMT;			/* For s_prf */
NODE	*varCONVFMT;			/* For internal conv of float to str */
NODE	*varOFS;			/* For s_print */
NODE	*varORS;			/* For s_print */
NODE	*varFS;				/* Field separtor */
NODE	*varRS;				/* Record separator */
NODE	*varARGC;			/* Quick access to ARGC */
NODE	*varSUBSEP;			/* Quick access to SUBSEP */
NODE	*varENVIRON;			/* Pointer to ENVIRON variable */
NODE	*varSYMTAB;			/* Symbol table special variable */
NODE	*varFILENAME;			/* Node for FILENAME variable */
NODE	*curnode;			/* Pointer to current line */
NODE	*inc_oper;			/* used by INC/DEC in awk3.c */
NODE	*asn_oper;			/* used by AADD, etc in awk3.c */
