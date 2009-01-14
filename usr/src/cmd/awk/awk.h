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

#ifndef AWK_H
#define	AWK_H

#include <sys/types.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libintl.h>
#include <limits.h>

typedef double	Awkfloat;
typedef	unsigned char uchar;

#define	xfree(a)	{ if ((a) != NULL) { free(a); a = NULL; } }

#define	DEBUG
#ifdef	DEBUG
			/* uses have to be doubly parenthesized */
#define	dprintf(x)	if (dbg) (void) printf x
#else
#define	dprintf(x)
#endif

extern	char	errbuf[200];
extern	void	error(int, char *);
#define	ERROR	(void) snprintf(errbuf, sizeof (errbuf),
/*CSTYLED*/
#define	FATAL	), error(1, errbuf)
/*CSTYLED*/
#define	WARNING	), error(0, errbuf)
/*CSTYLED*/
#define	SYNTAX	), yyerror(errbuf)
/*CSTYLED*/
#define	CONT	)

extern int	compile_time;	/* 1 if compiling, 0 if running */

#define	FLD_INCR	64
#define	LINE_INCR	256

/* ensure that there is extra 1 byte in the buffer */
#define	expand_buf(p, n, r)	\
	if (*(n) == 0 || (r) >= (*(n) - 1)) r_expand_buf(p, n, r)

extern uchar	**FS;
extern uchar	**RS;
extern uchar	**ORS;
extern uchar	**OFS;
extern uchar	**OFMT;
extern Awkfloat *NR;
extern Awkfloat *FNR;
extern Awkfloat *NF;
extern uchar	**FILENAME;
extern uchar	**SUBSEP;
extern Awkfloat *RSTART;
extern Awkfloat *RLENGTH;

extern uchar	*record;
extern size_t	record_size;
extern int	errorflag;
extern int	donefld;	/* 1 if record broken into fields */
extern int	donerec;	/* 1 if record is valid (no fld has changed */

extern	uchar	*patbeg;	/* beginning of pattern matched */
extern	int	patlen;		/* length.  set in b.c */

/* Cell:  all information about a variable or constant */

typedef struct Cell {
	uchar	ctype;		/* OCELL, OBOOL, OJUMP, etc. */
	uchar	csub;		/* CCON, CTEMP, CFLD, etc. */
	uchar	*nval;		/* name, for variables only */
	uchar	*sval;		/* string value */
	Awkfloat fval;		/* value as number */
	unsigned tval;
		/* type info: STR|NUM|ARR|FCN|FLD|CON|DONTFREE */
	struct Cell *cnext;	/* ptr to next if chained */
} Cell;

typedef struct {		/* symbol table array */
	int	nelem;		/* elements in table right now */
	int	size;		/* size of tab */
	Cell	**tab;		/* hash table pointers */
} Array;

#define	NSYMTAB	50	/* initial size of a symbol table */
extern Array	*symtab, *makesymtab(int);
extern Cell	*setsymtab(uchar *, uchar *, Awkfloat, unsigned int, Array *);
extern Cell	*lookup(uchar *, Array *);

extern Cell	*recloc;	/* location of input record */
extern Cell	*nrloc;		/* NR */
extern Cell	*fnrloc;	/* FNR */
extern Cell	*nfloc;		/* NF */
extern Cell	*rstartloc;	/* RSTART */
extern Cell	*rlengthloc;	/* RLENGTH */

/* Cell.tval values: */
#define	NUM	01	/* number value is valid */
#define	STR	02	/* string value is valid */
#define	DONTFREE 04	/* string space is not freeable */
#define	CON	010	/* this is a constant */
#define	ARR	020	/* this is an array */
#define	FCN	040	/* this is a function name */
#define	FLD	0100	/* this is a field $1, $2, ... */
#define	REC	0200	/* this is $0 */

#define	freeable(p)	(!((p)->tval & DONTFREE))

extern Awkfloat setfval(Cell *, Awkfloat), getfval(Cell *), r_getfval(Cell *);
extern uchar	*setsval(Cell *, uchar *), *getsval(Cell *), *r_getsval(Cell *);
extern uchar	*tostring(uchar *), *tokname(int), *qstring(uchar *, int);

#define	getfval(p)	\
	(((p)->tval & (ARR|FLD|REC|NUM)) == NUM ? (p)->fval : r_getfval(p))
#define	getsval(p)	\
	(((p)->tval & (ARR|FLD|REC|STR)) == STR ? (p)->sval : r_getsval(p))

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

/* Node:  parse tree is made of nodes, with Cell's at bottom */

typedef struct Node {
	int	ntype;
	struct	Node *nnext;
	off_t lineno;
	int	nobj;
	struct Node *narg[1];
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

/* bool subtypes */
#define	BTRUE	11
#define	BFALSE	12

/* jump subtypes */
#define	JEXIT	21
#define	JNEXT	22
#define	JBREAK	23
#define	JCONT	24
#define	JRET	25

/* node types */
#define	NVALUE	1
#define	NSTAT	2
#define	NEXPR	3
#define	NFIELD	4

extern	Cell	*(*proctab[])(Node **, int);
extern	Cell	*nullproc(Node **, int);
extern	int	pairstack[], paircnt;

extern	Node	*stat1(int, Node *), *stat2(int, Node *, Node *);
extern	Node	*stat3(int, Node *, Node *, Node *);
extern	Node	*stat4(int, Node *, Node *, Node *, Node *);
extern	Node	*pa2stat(Node *, Node *, Node *);
extern	Node	*op1(int, Node *), *op2(int, Node *, Node *);
extern	Node	*op3(int, Node *, Node *, Node *);
extern	Node	*op4(int, Node *, Node *, Node *, Node *);
extern	Node	*linkum(Node *, Node *), *valtonode(Cell *, int);
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
#define	isnext(n)	((n)->csub == JNEXT)
#define	isret(n)	((n)->csub == JRET)
#define	isstr(n)	((n)->tval & STR)
#define	isnum(n)	((n)->tval & NUM)
#define	isarr(n)	((n)->tval & ARR)
#define	isfunc(n)	((n)->tval & FCN)
#define	istrue(n)	((n)->csub == BTRUE)
#define	istemp(n)	((n)->csub == CTEMP)

#define	NCHARS	(256+1)
#define	NSTATES	32

typedef struct rrow {
	int	ltype;
	int	lval;
	int	*lfollow;
} rrow;

typedef struct fa {
	uchar	*restr;
	int	anchor;
	int	use;
	uchar	gototab[NSTATES][NCHARS];
	int	*posns[NSTATES];
	uchar	out[NSTATES];
	int	initstat;
	int	curstat;
	int	accept;
	int	reset;
	struct	rrow re[1];
} fa;

/* b.c */
extern	fa	*makedfa(uchar *, int);
extern	int	nematch(fa *, uchar *);
extern	int	match(fa *, uchar *);
extern	int	pmatch(fa *, uchar *);

/* lib.c */
extern	int	isclvar(uchar *);
extern	int	is_number(uchar *);
extern	void	setclvar(uchar *);
extern	int	readrec(uchar **, size_t *, FILE *);
extern	void	bracecheck(void);
extern	void	syminit(void);
extern	void	yyerror(char *);
extern	void	fldbld(void);
extern	void	recbld(void);
extern	int	getrec(uchar **, size_t *);
extern	Cell	*fieldadr(int);
extern	void	newfld(int);
extern	Cell	*getfld(int);
extern	int	fldidx(Cell *);
extern	double	errcheck(double, char *);
extern	void	fpecatch(int);
extern	void	init_buf(uchar **, size_t *, size_t);
extern	void	adjust_buf(uchar **, size_t);
extern	void	r_expand_buf(uchar **, size_t *, size_t);

extern	int	donefld;
extern	int	donerec;
extern	uchar	*record;
extern	size_t	record_size;

/* main.c */
extern	int	dbg;
extern	uchar	*cmdname;
extern	uchar	*lexprog;
extern	int	compile_time;
extern	char	radixpoint;

/* tran.c */
extern	void	syminit(void);
extern	void	arginit(int, uchar **);
extern	void	envinit(uchar **);
extern	void	freesymtab(Cell *);
extern	void	freeelem(Cell *, uchar *);
extern	void	funnyvar(Cell *, char *);
extern	int	hash(uchar *, int);
extern	Awkfloat *ARGC;

/* run.c */
extern	void	run(Node *);

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
extern Cell *a_sprintf(Node **, int);
extern Cell *arith(Node **, int);
extern Cell *incrdecr(Node **, int);
extern Cell *cat(Node **, int);
extern Cell *pastat(Node **, int);
extern Cell *dopa2(Node **, int);
extern Cell *matchop(Node **, int);
extern Cell *intest(Node **, int);
extern Cell *aprintf(Node **, int);
extern Cell *print(Node **, int);
extern Cell *closefile(Node **, int);
extern Cell *delete(Node **, int);
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
extern Cell *getline(Node **, int);

#endif /* AWK_H */
