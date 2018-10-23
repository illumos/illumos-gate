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
 * Copyright (c) 1989, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

#ifndef AWK_H
#define	AWK_H

#include <assert.h>
#include <sys/types.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libintl.h>
#include <limits.h>

typedef double	Awkfloat;

/* unsigned char is more trouble than it's worth */

typedef	unsigned char uschar;

#define	xfree(a)	{ if ((a) != NULL) { free((void *)(a)); (a) = NULL; } }

/* guaranteed non-null for dprintf */
#define	NN(p)	((p) ? (p) : "(null)")
#define	DEBUG
#ifdef	DEBUG
			/* uses have to be doubly parenthesized */
#define	dprintf(x)	if (dbg) (void) printf x
#else
#define	dprintf(x)
#endif

extern int	compile_time;	/* 1 if compiling, 0 if running */
extern int	safe;		/* 0 => unsafe, 1 => safe */

#define	FLD_INCR	64
#define	LINE_INCR	256
#define	RECSIZE	(8 * 1024)	/* sets limit on records, fields, etc., etc. */
extern size_t	recsize;	/* size of current record, orig RECSIZE */

/* ensure that there is extra 1 byte in the buffer */
#define	expand_buf(p, n, r)	\
	if (*(n) == 0 || (r) >= (*(n) - 1)) r_expand_buf(p, n, r)

extern char	**FS;
extern char	**RS;
extern char	**ORS;
extern char	**OFS;
extern char	**OFMT;
extern Awkfloat *NR;
extern Awkfloat *FNR;
extern Awkfloat *NF;
extern char	**FILENAME;
extern char	**SUBSEP;
extern Awkfloat *RSTART;
extern Awkfloat *RLENGTH;

extern char	*record;	/* points to $0 */
extern size_t	recsize;
extern int	errorflag;	/* 1 if error has occurred */
extern int	donefld;	/* 1 if record broken into fields */
extern int	donerec;	/* 1 if record is valid (no fld has changed */

extern	char	*patbeg;	/* beginning of pattern matched */
extern	int	patlen;		/* length of pattern matched. set in b.c */

/* Cell:  all information about a variable or constant */

typedef struct Cell {
	uschar	ctype;		/* OCELL, OBOOL, OJUMP, etc. */
	uschar	csub;		/* CCON, CTEMP, CFLD, etc. */
	char	*nval;		/* name, for variables only */
	char	*sval;		/* string value */
	Awkfloat fval;		/* value as number */
	int	 tval;
		/* type info: STR|NUM|ARR|FCN|FLD|CON|DONTFREE|CONVC|CONVO */
	char	*fmt;
		/* CONVFMT/OFMT value used to convert from number */
	struct Cell *cnext;	/* ptr to next if chained */
} Cell;

typedef struct Array {		/* symbol table array */
	int	nelem;		/* elements in table right now */
	int	size;		/* size of tab */
	Cell	**tab;		/* hash table pointers */
} Array;

#define	NSYMTAB	50	/* initial size of a symbol table */
extern Array	*symtab, *makesymtab(int);
extern Cell	*setsymtab(const char *, const char *, Awkfloat,
		    unsigned int, Array *);
extern Cell	*lookup(const char *, Array *);

extern Cell	*recloc;	/* location of input record */
extern Cell	*nrloc;		/* NR */
extern Cell	*fnrloc;	/* FNR */
extern Cell	*fsloc;		/* FS */
extern Cell	*nfloc;		/* NF */
extern Cell	*ofsloc;	/* OFS */
extern Cell	*orsloc;	/* ORS */
extern Cell	*rsloc;		/* RS */
extern Cell	*rtloc;		/* RT */
extern Cell	*rstartloc;	/* RSTART */
extern Cell	*rlengthloc;	/* RLENGTH */
extern Cell	*subseploc;	/* SUBSEP */
extern Cell	*symtabloc;	/* SYMTAB */

/* Cell.tval values: */
#define	NUM	01	/* number value is valid */
#define	STR	02	/* string value is valid */
#define	DONTFREE 04	/* string space is not freeable */
#define	CON	010	/* this is a constant */
#define	ARR	020	/* this is an array */
#define	FCN	040	/* this is a function name */
#define	FLD	0100	/* this is a field $1, $2, ... */
#define	REC	0200	/* this is $0 */
#define	CONVC	0400	/* string was converted from number via CONVFMT */
#define	CONVO	01000	/* string was converted from number via OFMT */


extern Awkfloat	setfval(Cell *, Awkfloat);
extern Awkfloat	getfval(Cell *);
extern char	*setsval(Cell *, const char *);
extern char	*getsval(Cell *);
extern char	*getpssval(Cell *);	/* for print */
extern char	*tostring(const char *);
extern char	*tokname(int);
extern char	*qstring(const char *, int);

/* function types */
#define	FLENGTH	1
#define	FSQRT	2
#define	FEXP	3
#define	FLOG	4
#define	FINT	5
#define	FSYSTEM	6
#define	FRAND	7
#define	FSRAND	8
#define	FSIN	9
#define	FCOS	10
#define	FATAN	11
#define	FTOUPPER 12
#define	FTOLOWER 13
#define	FFLUSH	14

/* Node:  parse tree is made of nodes, with Cell's at bottom */

typedef struct Node {
	int	ntype;
	struct	Node *nnext;
	off_t	lineno;
	int	nobj;
	struct	Node *narg[1];
		/* variable: actual size set by calling malloc */
} Node;

#define	NIL	((Node *)0)

extern Node	*winner;
extern Node	*nullstat;
extern Node	*nullnode;

/* ctypes */
#define	OCELL	1
#define	OBOOL	2
#define	OJUMP	3

/* Cell subtypes: csub */
#define	CFREE	7
#define	CCOPY	6
#define	CCON	5
#define	CTEMP	4
#define	CNAME	3
#define	CVAR	2
#define	CFLD	1
#define	CUNK	0

/* bool subtypes */
#define	BTRUE	11
#define	BFALSE	12

/* jump subtypes */
#define	JEXIT	21
#define	JNEXT	22
#define	JBREAK	23
#define	JCONT	24
#define	JRET	25
#define	JNEXTFILE	26

/* node types */
#define	NVALUE	1
#define	NSTAT	2
#define	NEXPR	3
#define	NFIELD	4

extern	Cell	*(*proctab[])(Node **, int);
extern	Cell	*nullproc(Node **, int);
extern	int	*pairstack, paircnt;

extern	Node	*stat1(int, Node *), *stat2(int, Node *, Node *);
extern	Node	*stat3(int, Node *, Node *, Node *);
extern	Node	*stat4(int, Node *, Node *, Node *, Node *);
extern	Node	*pa2stat(Node *, Node *, Node *);
extern	Node	*op1(int, Node *), *op2(int, Node *, Node *);
extern	Node	*op3(int, Node *, Node *, Node *);
extern	Node	*op4(int, Node *, Node *, Node *, Node *);
extern	Node	*linkum(Node *, Node *), *celltonode(Cell *, int);
extern	Node	*rectonode(void), *exptostat(Node *);
extern	Node	*makearr(Node *);

#define	notlegal(n)	\
	(n <= FIRSTTOKEN || n >= LASTTOKEN || proctab[n-FIRSTTOKEN] == nullproc)
#define	isvalue(n)	((n)->ntype == NVALUE)
#define	isexpr(n)	((n)->ntype == NEXPR)
#define	isjump(n)	((n)->ctype == OJUMP)
#define	isexit(n)	((n)->csub == JEXIT)
#define	isbreak(n)	((n)->csub == JBREAK)
#define	iscont(n)	((n)->csub == JCONT)
#define	isnext(n)	((n)->csub == JNEXT || (n)->csub == JNEXTFILE)
#define	isret(n)	((n)->csub == JRET)
#define	isrec(n)	((n)->tval & REC)
#define	isfld(n)	((n)->tval & FLD)
#define	isstr(n)	((n)->tval & STR)
#define	isnum(n)	((n)->tval & NUM)
#define	isarr(n)	((n)->tval & ARR)
#define	isfcn(n)	((n)->tval & FCN)
#define	istrue(n)	((n)->csub == BTRUE)
#define	istemp(n)	((n)->csub == CTEMP)
#define	freeable(p)	(((p)->tval & (STR|DONTFREE)) == STR)

/* structures used by regular expression matching machinery, mostly b.c: */

/* 256 handles 8-bit chars; 128 does 7-bit */
/* watch out in match(), etc. */
#define	NCHARS	(256+3)
#define	NSTATES	32

typedef struct rrow {
	long	ltype;	/* long avoids pointer warnings on 64-bit */
	union {
		int i;
		Node *np;
		uschar *up;
	} lval;		/* because Al stores a pointer in it! */
	int	*lfollow;
} rrow;

typedef struct fa {
	uschar	gototab[NSTATES][NCHARS];
	uschar	out[NSTATES];
	uschar	*restr;
	int	*posns[NSTATES];
	int	anchor;
	int	use;
	int	initstat;
	int	curstat;
	int	accept;
	int	reset;
	/* re is variable: actual size set by calling malloc */
	struct	rrow re[1];
} fa;

/* lex.c */
extern	int	yylex(void);
extern	void	startreg(void);
extern	int	input(void);
extern	void	unput(int);
extern	void	unputstr(const char *);
extern	int	yylook(void);
extern	int	yyback(int *, int);
extern	int	yyinput(void);

/* parse.c */
extern	void	defn(Cell *, Node *, Node *);
extern	int	ptoi(void *);
extern	Node	*itonp(int);
extern	int	isarg(const char *);

/* b.c */
extern	fa	*makedfa(const char *, int);
extern	int	nematch(fa *, const char *);
extern	int	match(fa *, const char *);
extern	int	pmatch(fa *, const char *);

/* lib.c */

extern	void	SYNTAX(const char *, ...);
extern	void	FATAL(const char *, ...) __attribute__((__noreturn__));
extern	void	WARNING(const char *, ...);
extern	void	error(void);
extern	void	nextfile(void);
extern	void	savefs(void);

extern	int	isclvar(const char *);
extern	int	is_number(const char *);
extern	void	setclvar(char *);
extern	int	readrec(char **, size_t *, FILE *);
extern	void	bracecheck(void);
extern	void	recinit(unsigned int n);
extern	void	syminit(void);
extern	void	yyerror(const char *);
extern	void	fldbld(void);
extern	void	recbld(void);
extern	int	getrec(char **, size_t *, int);
extern	Cell	*fieldadr(int);
extern	void	newfld(int);
extern	int	fldidx(Cell *);
extern	double	errcheck(double, const char *);
extern	void	fpecatch(int);
extern	void	r_expand_buf(char **, size_t *, size_t);
extern	void	makefields(int, int);
extern	void	growfldtab(int n);
extern	void	setlastfld(int n);

/* main.c */
extern	int	dbg;
extern	char	*lexprog;
extern	int	compile_time;
extern	char	*cursource(void);
extern	int	pgetc(void);

/* tran.c */
extern	void	syminit(void);
extern	void	arginit(int, char **);
extern	void	envinit(char **);
extern	void	freesymtab(Cell *);
extern	void	freeelem(Cell *, const char *);
extern	void	funnyvar(Cell *, const char *);
extern	int	hash(const char *, int);
extern	Awkfloat *ARGC;

/* run.c */
extern	void		run(Node *);
extern	const char	*filename(FILE *);
extern	int		adjbuf(char **pb, size_t *sz, size_t min, size_t q,
			    char **pbp, const char *what);

extern	int	paircnt;
extern	Node	*winner;

#ifndef input
extern	int	input(void);
#endif
extern	int	yyparse(void);
extern	FILE	*yyin;
extern	off_t	lineno;

/* proc */
extern Cell *nullproc(Node **, int);
extern Cell *program(Node **, int);
extern Cell *boolop(Node **, int);
extern Cell *relop(Node **, int);
extern Cell *array(Node **, int);
extern Cell *indirect(Node **, int);
extern Cell *substr(Node **, int);
extern Cell *sub(Node **, int);
extern Cell *gsub(Node **, int);
extern Cell *sindex(Node **, int);
extern Cell *awksprintf(Node **, int);
extern Cell *arith(Node **, int);
extern Cell *incrdecr(Node **, int);
extern Cell *cat(Node **, int);
extern Cell *pastat(Node **, int);
extern Cell *dopa2(Node **, int);
extern Cell *matchop(Node **, int);
extern Cell *intest(Node **, int);
extern Cell *awkprintf(Node **, int);
extern Cell *printstat(Node **, int);
extern Cell *closefile(Node **, int);
extern Cell *awkdelete(Node **, int);
extern Cell *split(Node **, int);
extern Cell *assign(Node **, int);
extern Cell *condexpr(Node **, int);
extern Cell *ifstat(Node **, int);
extern Cell *whilestat(Node **, int);
extern Cell *forstat(Node **, int);
extern Cell *dostat(Node **, int);
extern Cell *instat(Node **, int);
extern Cell *jump(Node **, int);
extern Cell *bltin(Node **, int);
extern Cell *call(Node **, int);
extern Cell *arg(Node **, int);
extern Cell *getnf(Node **, int);
extern Cell *awkgetline(Node **, int);

#endif /* AWK_H */
