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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/* Copyright (c) 1988 AT&T */
/* All Rights Reserved */

#ifndef _DEXTERN_H
#define	_DEXTERN_H

#include <stdio.h>
#include <inttypes.h>
#include <ctype.h>
#include <memory.h>
#include <string.h>
#include <malloc.h>
#include <values.h>
#include <widec.h>
#include <unistd.h>
#include <stdlib.h>
#include <wctype.h>

#ifdef	__cplusplus
extern "C" {
#endif

	/*  MANIFEST CONSTANT DEFINITIONS */
#if u3b || u3b15 || u3b2 || vax || uts || sparc
#define	WORD32
#endif
#include <libintl.h>

	/* base of nonterminal internal numbers */

#define	NTBASE (10000000)

	/* internal codes for error and accept actions */

#define	ERRCODE  8190
#define	ACCEPTCODE 8191

	/* sizes and limits */

#define	ACTSIZE 4000
#define	MEMSIZE 2000
#define	PSTSIZE 1024
#define	NSTATES 1000
#define	NTERMS 127
#define	NPROD 300
#define	NNONTERM 600
#define	TEMPSIZE 800
#define	CNAMSZ 1000
#define	LSETSIZE 950
#define	WSETSIZE 850

#define	NAMESIZE 50
#define	NTYPES 1000

#define	NMBCHARSZ 100
#define	LKFACTOR 5

#ifdef WORD32
	/* bit packing macros (may be machine dependent) */
#define	BIT(a, i) ((a)[(i)>>5] & (1<<((i)&037)))
#define	SETBIT(a, i) ((a)[(i)>>5] |= (1<<((i)&037)))

	/* number of words needed to hold n+1 bits */
#define	NWORDS(n) (((n)+32)/32)

#else

	/* bit packing macros (may be machine dependent) */
#define	BIT(a, i) ((a)[(i)>>4] & (1<<((i)&017)))
#define	SETBIT(a, i) ((a)[(i)>>4] |= (1<<((i)&017)))

	/* number of words needed to hold n+1 bits */
#define	NWORDS(n) (((n)+16)/16)
#endif

	/*
	 * relationships which must hold:
	 * TBITSET ints must hold NTERMS+1 bits...
	 * WSETSIZE >= NNONTERM
	 * LSETSIZE >= NNONTERM
	 * TEMPSIZE >= NTERMS + NNONTERMs + 1
	 * TEMPSIZE >= NSTATES
	 */

	/* associativities */

#define	NOASC 0  /* no assoc. */
#define	LASC 1  /* left assoc. */
#define	RASC 2  /* right assoc. */
#define	BASC 3  /* binary assoc. */

	/* flags for state generation */

#define	DONE 0
#define	MUSTDO 1
#define	MUSTLOOKAHEAD 2

	/* flags for a rule having an action, and being reduced */

#define	ACTFLAG 04
#define	REDFLAG 010

	/* output parser flags */
#define	YYFLAG1 (-10000000)

	/* macros for getting associativity and precedence levels */

#define	ASSOC(i) ((i)&07)
#define	PLEVEL(i) (((i)>>4)&077)
#define	TYPE(i)  ((i>>10)&077)

	/* macros for setting associativity and precedence levels */

#define	SETASC(i, j) i |= j
#define	SETPLEV(i, j) i |= (j<<4)
#define	SETTYPE(i, j) i |= (j<<10)

	/* looping macros */

#define	TLOOP(i) for (i = 1; i <= ntokens; ++i)
#define	NTLOOP(i) for (i = 0; i <= nnonter; ++i)
#define	PLOOP(s, i) for (i = s; i < nprod; ++i)
#define	SLOOP(i) for (i = 0; i < nstate; ++i)
#define	WSBUMP(x) ++x
#define	WSLOOP(s, j) for (j = s; j < &wsets[cwp]; ++j)
#define	ITMLOOP(i, p, q) q = pstate[i+1]; for (p = pstate[i]; p < q; ++p)
#define	SETLOOP(i) for (i = 0; i < tbitset; ++i)

	/* I/O descriptors */

extern FILE *finput;		/* input file */
extern FILE *faction;		/* file for saving actions */
extern FILE *fdefine;		/* file for #defines */
extern FILE *ftable;		/* y.tab.c file */
extern FILE *ftemp;		/* tempfile to pass 2 */
extern FILE *fdebug;		/* tempfile for two debugging info arrays */
extern FILE *foutput;		/* y.output file */

	/* structure declarations */

typedef struct looksets {
	int *lset;
} LOOKSETS;

typedef struct item {
	int *pitem;
	LOOKSETS *look;
} ITEM;

typedef struct toksymb {
	wchar_t *name;
	int value;
} TOKSYMB;

typedef struct mbclit {
	wchar_t character;
	int tvalue; /* token issued for the character */
} MBCLIT;

typedef struct ntsymb {
	wchar_t *name;
	int tvalue;
} NTSYMB;

typedef struct wset {
	int *pitem;
	int flag;
	LOOKSETS ws;
} WSET;

	/* token information */

extern int ntokens;	/* number of tokens */
extern TOKSYMB *tokset;
extern int ntoksz;

	/*
	 * multibyte (c > 255) character literals are
	 * handled as though they were tokens except
	 * that it generates a separate mapping table.
	 */
extern int nmbchars;	/* number of mb literals */
extern MBCLIT *mbchars;
extern int nmbcharsz;

	/* nonterminal information */

extern int nnonter;	/* the number of nonterminals */
extern NTSYMB *nontrst;
extern int nnontersz;

	/* grammar rule information */

extern int nprod;	/* number of productions */
extern int **prdptr;	/* pointers to descriptions of productions */
extern int *levprd;	/* contains production levels to break conflicts */
extern wchar_t *had_act; /* set if reduction has associated action code */

	/* state information */

extern int nstate;		/* number of states */
extern ITEM **pstate;	/* pointers to the descriptions of the states */
extern int *tystate;	/* contains type information about the states */
extern int *defact;	/* the default action of the state */

extern int size;

	/* lookahead set information */

extern int TBITSET;
extern LOOKSETS *lkst;
extern int nolook;  /* flag to turn off lookahead computations */

	/* working set information */

extern WSET *wsets;

	/* storage for productions */

extern int *mem0;
extern int *mem;
extern int *tracemem;
extern int new_memsize;

	/* storage for action table */

extern int *amem;
extern int *memp;		/* next free action table position */
extern int *indgo;		/* index to the stored goto table */
extern int new_actsize;

	/* temporary vector, indexable by states, terms, or ntokens */

extern int *temp1;
extern int lineno; /* current line number */

	/* statistics collection variables */

extern int zzgoent;
extern int zzgobest;
extern int zzacent;
extern int zzexcp;
extern int zzrrconf;
extern int zzsrconf;

	/* define external functions */

extern void setup(int, char *[]);
extern void closure(int);
extern void output(void);
extern void aryfil(int *, int, int);
extern void error(char *, ...);
extern void warning(int, char *, ...);
extern void putitem(int *, LOOKSETS *);
extern void go2out(void);
extern void hideprod(void);
extern void callopt(void);
extern void warray(wchar_t *, int *, int);
extern wchar_t *symnam(int);
extern wchar_t *writem(int *);
extern void exp_mem(int);
extern void exp_act(int **);
extern int apack(int *, int);
extern int state(int);
extern void fprintf3(FILE *, const char *, const wchar_t *, const char *, ...);
extern void error3(const char *, const wchar_t *, const char *, ...);

extern wchar_t *wscpy(wchar_t *, const wchar_t *);
extern size_t wslen(const wchar_t *);
extern int wscmp(const wchar_t *, const wchar_t *);


	/* yaccpar location */

extern char *parser;

	/* default settings for a number of macros */

	/* name of yacc tempfiles */

#ifndef TEMPNAME
#define	TEMPNAME "yacc.tmp"
#endif

#ifndef ACTNAME
#define	ACTNAME "yacc.acts"
#endif

#ifndef DEBUGNAME
#define	DEBUGNAME "yacc.debug"
#endif

	/* command to clobber tempfiles after use */

#ifndef ZAPFILE
#define	ZAPFILE(x) (void)unlink(x)
#endif

#ifndef PARSER
#define	PARSER "/usr/share/lib/ccs/yaccpar"
#endif

#ifdef	__cplusplus
}
#endif

#endif /* _DEXTERN_H */
