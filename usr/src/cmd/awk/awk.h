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
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * Copyright (c) 1996, 2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 2.13	*/

#include <sys/types.h>
#include <limits.h>

typedef double	Awkfloat;
typedef	unsigned char uchar;

#define	xfree(a)	{ if ((a) != NULL) { free(a); a = NULL; } }

#define	DEBUG
#ifdef	DEBUG
			/* uses have to be doubly parenthesized */
#	define	dprintf(x)	if (dbg) printf x
#else
#	define	dprintf(x)
#endif

extern	char	errbuf[200];
#define	ERROR	sprintf(errbuf,
#define	FATAL	), error(1, errbuf)
#define	WARNING	), error(0, errbuf)
#define	SYNTAX	), yyerror(errbuf)

extern int	compile_time;	/* 1 if compiling, 0 if running */

/* The standards (SUSV2) requires that Record size be atleast LINE_MAX.
 * LINE_MAX is standard variable defined in limits.h.
 * Though nawk is not standards compliant, we let RECSIZE
 * grow with LINE_MAX instead of magic number 1024.
 */
#define	RECSIZE	(3 * LINE_MAX)	/* sets limit on records, fields, etc., etc. */

#define	MAXFLD	500

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
extern int	dbg;
extern off_t	lineno;
extern int	errorflag;
extern int	donefld;	/* 1 if record broken into fields */
extern int	donerec;	/* 1 if record is valid (no fld has changed */

extern uchar	cbuf[RECSIZE];	/* miscellaneous character collection */

extern	uchar	*patbeg;	/* beginning of pattern matched */
extern	int	patlen;		/* length.  set in b.c */

/* Cell:  all information about a variable or constant */

typedef struct Cell {
	uchar	ctype;		/* OCELL, OBOOL, OJUMP, etc. */
	uchar	csub;		/* CCON, CTEMP, CFLD, etc. */
	uchar	*nval;		/* name, for variables only */
	uchar	*sval;		/* string value */
	Awkfloat fval;		/* value as number */
	unsigned tval;		/* type info: STR|NUM|ARR|FCN|FLD|CON|DONTFREE */
	struct Cell *cnext;	/* ptr to next if chained */
} Cell;

typedef struct {		/* symbol table array */
	int	nelem;		/* elements in table right now */
	int	size;		/* size of tab */
	Cell	**tab;		/* hash table pointers */
} Array;

#define	NSYMTAB	50	/* initial size of a symbol table */
extern Array	*symtab, *makesymtab();
extern Cell	*setsymtab(), *lookup();

extern Cell	*recloc;	/* location of input record */
extern Cell	*nrloc;		/* NR */
extern Cell	*fnrloc;	/* FNR */
extern Cell	*nfloc;		/* NF */
extern Cell	*rstartloc;	/* RSTART */
extern Cell	*rlengthloc;	/* RLENGTH */

/* Cell.tval values: */
#define	NUM	01	/* number value is valid */
#define	STR	02	/* string value is valid */
#define DONTFREE 04	/* string space is not freeable */
#define	CON	010	/* this is a constant */
#define	ARR	020	/* this is an array */
#define	FCN	040	/* this is a function name */
#define FLD	0100	/* this is a field $1, $2, ... */
#define	REC	0200	/* this is $0 */

#define freeable(p)	(!((p)->tval & DONTFREE))

Awkfloat setfval(), getfval();
uchar	*setsval(), *getsval();
uchar	*tostring(), *tokname(), *qstring();

double	log(), sqrt(), exp(), atof();

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
	struct Node *narg[1];	/* variable: actual size set by calling malloc */
} Node;

#define	NIL	((Node *) 0)

extern Node	*winner;
extern Node	*nullstat;
extern Node	*nullnode;

/* ctypes */
#define OCELL	1
#define OBOOL	2
#define OJUMP	3

/* Cell subtypes: csub */
#define	CFREE	7
#define CCOPY	6
#define CCON	5
#define CTEMP	4
#define CNAME	3 
#define CVAR	2
#define CFLD	1

/* bool subtypes */
#define BTRUE	11
#define BFALSE	12

/* jump subtypes */
#define JEXIT	21
#define JNEXT	22
#define	JBREAK	23
#define	JCONT	24
#define	JRET	25

/* node types */
#define NVALUE	1
#define NSTAT	2
#define NEXPR	3
#define	NFIELD	4

extern	Cell	*(*proctab[])();
extern	Cell	*nullproc();
extern	int	pairstack[], paircnt;
extern	Cell	*fieldadr();

extern	Node	*stat1(), *stat2(), *stat3(), *stat4(), *pa2stat();
extern	Node	*op1(), *op2(), *op3(), *op4();
extern	Node	*linkum(), *valtonode(), *rectonode(), *exptostat();
extern	Node	*makearr();

#define notlegal(n)	(n <= FIRSTTOKEN || n >= LASTTOKEN || proctab[n-FIRSTTOKEN] == nullproc)
#define isvalue(n)	((n)->ntype == NVALUE)
#define isexpr(n)	((n)->ntype == NEXPR)
#define isjump(n)	((n)->ctype == OJUMP)
#define isexit(n)	((n)->csub == JEXIT)
#define	isbreak(n)	((n)->csub == JBREAK)
#define	iscont(n)	((n)->csub == JCONT)
#define	isnext(n)	((n)->csub == JNEXT)
#define	isret(n)	((n)->csub == JRET)
#define isstr(n)	((n)->tval & STR)
#define isnum(n)	((n)->tval & NUM)
#define isarr(n)	((n)->tval & ARR)
#define isfunc(n)	((n)->tval & FCN)
#define istrue(n)	((n)->csub == BTRUE)
#define istemp(n)	((n)->csub == CTEMP)

#define NCHARS	(256+1)
#define NSTATES	32

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

extern	fa	*makedfa();
