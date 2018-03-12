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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * awk -- common header file.
 *
 * Copyright 1986, 1994 by Mortice Kern Systems Inc.  All rights reserved.
 *
 * This version uses the POSIX.2 compatible <regex.h> routines.
 *
 * Based on MKS awk(1) ported to be /usr/xpg4/bin/awk with POSIX/XCU4 changes
 *
 */

#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <math.h>
#include <limits.h>
#include <stdlib.h>
#include <regex.h>
#include <errno.h>
#include <sys/types.h>
#include <locale.h>
#include <wchar.h>
#include <widec.h>

#define	YYMAXDEPTH	300	/* Max # of productions (used by yacc) */
#define	YYSSIZE		300	/* Size of State/Value stacks (MKS YACC) */
#define	MAXDIGINT	19	/* Number of digits in an INT */
#define	FNULL		((FILE *)0)
#define	NNULL		((NODE *)0)
#define	SNULL		((STRING)0)
#define	LARGE		INT_MAX	/* Large integer */
#define	NPFILE		32	/* Number of -[fl] options allowed */
#define	NRECUR		3000	/* Maximum recursion depth */

#define	M_LDATA	1
#ifdef M_LDATA
#define	NLINE	20000	/* Longest input record */
#define	NFIELD	4000	/* Number of fields allowed */
#define	NBUCKET	1024	/* # of symtab buckets (power of 2) */
#else
#define	NLINE	2048	/* Longest input record */
#define	NFIELD	1024	/* Number of fields allowed */
#define	NBUCKET	256	/* # of symtab buckets (power of 2) */
#endif

#define	NSNODE		40	/* Number of cached nodes */
#define	NCONTEXT	50	/* Amount of context for error msgs */
#define	hashbuck(n)	((n)&(NBUCKET-1))
#if	BSD
/*
 * A speedup for BSD.  Use their routines which are
 * already optimised.  Note that BSD bcopy does not
 * return a value.
 */
int	bcmp();
#define	memcmp(b1, b2, n)	bcmp(b1, b2, n)
void	bcopy();
#define	memcpy(b1, b2, n)	bcopy(b2, b1, (int)n)
#endif	/* BSD */
#define	vlook(n)	vlookup(n, 0)

/*
 * Basic AWK internal types.
 */
typedef	double		REAL;
typedef	long long	INT;
typedef	wchar_t		*STRING;
typedef	struct NODE	*(*FUNCTION)(struct NODE *np);
typedef	void		*REGEXP;

/*
 * Node in the AWK interpreter expression tree.
 */
typedef	struct	NODE	{
	ushort_t	n_type;
	struct NODE	*n_next;		/* Symbol table/PARM link */
	ushort_t	n_flags;		/* Node flags, type */




	union	{
		struct	{
			ushort_t	N_hash;		/* Full hash value */
			struct NODE	*N_alink;	/* Array link */
			union	{
				struct	{
					STRING	N_string;
					size_t	N_strlen;
				}	n_str;
				INT	N_int;
				REAL	N_real;
				FUNCTION	N_function;
				struct	NODE	*N_ufunc;
			}	n_tun;
			wchar_t	N_name[1];
		}	n_term;
		struct	{
			struct	NODE	*N_left;
			struct	NODE	*N_right;
			ushort_t	N_lineno;
		}	n_op;
		struct {
			struct	NODE	*N_left;	/* Used for fliplist */
			struct	NODE	*N_right;
			REGEXP		N_regexp;	/* Regular expression */
		}	n_re;
	}	n_un;
}	NODE;

/*
 * Definitions to make the node access much easier.
 */
#define	n_hash		n_un.n_term.N_hash	/* full hash value is sym tbl */
#define	n_scope		n_un.n_term.N_hash	/* local variable scope level */
#define	n_alink		n_un.n_term.N_alink	/* link to array list */
#define	n_string	n_un.n_term.n_tun.n_str.N_string
#define	n_strlen	n_un.n_term.n_tun.n_str.N_strlen
#define	n_int		n_un.n_term.n_tun.N_int
#define	n_real		n_un.n_term.n_tun.N_real
#define	n_function	n_un.n_term.n_tun.N_function
#define	n_ufunc		n_un.n_term.n_tun.N_ufunc
#define	n_name		n_un.n_term.N_name
#define	n_left		n_un.n_op.N_left
#define	n_right		n_un.n_op.N_right
#define	n_lineno	n_un.n_op.N_lineno
#define	n_keywtype	n_un.n_op.N_lineno
#define	n_regexp	n_un.n_re.N_regexp
/*
 * Compress the types that are actually used in the final tree
 * to save space in the intermediate file. Allows 1 byte to
 * represent all types
 */







/*
 * n_flags bit assignments.
 */
#define	FALLOC		0x01	/* Allocated node */
#define	FSTATIC		0x00	/* Not allocated */
#define	FMATCH		0x02	/* pattern,pattern (first part matches) */
#define	FSPECIAL	0x04	/* Special pre-computed variable */
#define	FINARRAY	0x08	/* NODE installed in N_alink array list */
#define	FNOALLOC	0x10	/* mark node FALLOC, but don't malloc */
#define	FSENSE		0x20	/* Sense if string looks like INT/REAL */
#define	FSAVE		(FSPECIAL|FINARRAY)	/* assign leaves on */

#define	FINT		0x40	/* Node has integer type */
#define	FREAL		0x80	/* Node has real type */
#define	FSTRING		0x100	/* Node has string type */
#define	FNONTOK		0x200	/* Node has non-token type */
#define	FVINT		0x400	/* Node looks like an integer */
#define	FVREAL		0x800	/* Node looks like a real number */
#define	FLARRAY		0x1000	/* Local array node */

/*
 * n_flags macros
 * These work when given an argument of np->n_flags
 */
#define	isleaf(f)	(!((f)&FNONTOK))
#define	isstring(f)	((f)&FSTRING)
#define	isastring(f)	(((f)&(FSTRING|FALLOC)) == (FSTRING|FALLOC))
#define	isnumber(f)	((f)&(FINT|FVINT|FREAL|FVREAL))
#define	isreal(f)	((f)&(FREAL|FVREAL))
#define	isint(f)	((f)&(FINT|FVINT))

/*
 * Prototype file size is defined in awksize.h
 */





/*
 * Awkrun prototype default name
 */
#if defined(DOS)
#if defined(__386__)
#define	AWK_PROTOTYPE  M_ETCDIR(awkrunf.dos)
#define	AWK_LPROTOTYPE M_ETCDIR(awkrunf.dos)
#else
#define	AWK_PROTOTYPE  M_ETCDIR(awkrun.dos)
#define	AWK_LPROTOTYPE M_ETCDIR(awkrunl.dos)
#endif
#elif defined(OS2)
#define	AWK_PROTOTYPE M_ETCDIR(awkrun.os2)
#elif defined(NT)
#define	AWK_PROTOTYPE M_ETCDIR(awkrun.nt)
#else
#define	AWK_PROTOTYPE M_ETCDIR(awkrun.mod)
#endif

/*
 * This is a kludge that gets around a bug in compact & large
 * models under DOS.  It also makes the generated
 * code faster even if there wasn't a bug.  UNIX people: try
 * to ignore these noisy "near" declarations.
 */
#ifndef	DOS
#define	near
#endif

typedef	wchar_t	near	*LOCCHARP;	/* pointer to local strings */
/*
 * Form of builtin symbols
 * This should be a union because only one of r_ivalue
 * and r_svalue is needed, but (alas) unions cannot be
 * initialised.
 */
typedef	struct	RESERVED {
	LOCCHARP	r_name;
	int		r_type;		/* Type of node */
	INT		r_ivalue;	/* Integer value or wcslen(r_svalue) */
	STRING		r_svalue;	/* String value */
}	RESERVED;

/*
 * Table of builtin functions.
 */
typedef	struct	RESFUNC {
	LOCCHARP	rf_name;
	int		rf_type;	/* FUNC || GETLINE */
	FUNCTION	rf_func;	/* Function pointer */
}	RESFUNC;

/*
 * Structure holding list of open files.
 */
typedef	struct	OFILE	{
	ushort_t f_mode;		/* Open mode: WRITE, APPEND, PIPE */
	FILE	*f_fp;			/* File pointer if open */
	char	*f_name;		/* Remembered file name */
}	OFILE;

/* Global functions -- awk.y */
int	yyparse(void);

/* Global functions -- awk1.c */
#ifdef __WATCOMC__
#pragma aux yyerror aborts;
#pragma aux awkerr aborts;
#pragma aux awkperr aborts;
#endif
void	yyerror(char *msg, ...);
void	awkerr(char *fmt, ...) __NORETURN;
void	awkperr(char *fmt, ...);
void	uexit(NODE *);
int	yylex(void);
NODE	*renode(wchar_t *restr);
wchar_t	*emalloc(unsigned);
wchar_t	*erealloc(wchar_t *, unsigned);

/* Global functions -- awk2.c */
void	awk(void);
void	dobegin(void);
void	doend(int status) __NORETURN;
int	nextrecord(wchar_t *buf, FILE *fp);
wchar_t	*defrecord(wchar_t *bp, int lim, FILE *fp);
wchar_t	*charrecord(wchar_t *bp, int lim, FILE *fp);
wchar_t	*multirecord(wchar_t *bp, int lim, FILE *fp);
wchar_t	*whitefield(wchar_t **endp);
wchar_t	*blackfield(wchar_t **endp);
wchar_t	*refield(wchar_t **endp);
void	s_print(NODE *np);
void	s_prf(NODE *np);
size_t	xprintf(NODE *np, FILE *fp, wchar_t **cp);
void	awkclose(OFILE *op);

/* Global functions -- awk3.c */
void	strassign(NODE *np, STRING string, int flags, size_t length);
NODE	*nassign(NODE *np, NODE *value);
NODE	*assign(NODE *np, NODE *value);
void	delarray(NODE *np);
NODE	*node(int type, NODE *left, NODE *right);
NODE	*intnode(INT i);
NODE	*realnode(REAL r);
NODE	*stringnode(STRING str, int aflag, size_t wcslen);
NODE	*vlookup(wchar_t *name, int nocreate);
NODE	*emptynode(int type, size_t nlength);
void	freenode(NODE *np);
void	execute(NODE *np);
INT	exprint(NODE *np);
REAL	exprreal(NODE *np);
STRING	exprstring(NODE *np);
STRING	strsave(wchar_t *string);
NODE	*exprreduce(NODE *np);
NODE	*getlist(NODE **npp);
NODE	*symwalk(int *buckp, NODE **npp);
REGEXP	getregexp(NODE *np);
void	addsymtab(NODE *np);
void	delsymtab(NODE *np, int fflag);
NODE	* finstall(LOCCHARP name, FUNCTION f, int type);
void	kinstall(LOCCHARP name, int type);
void	fieldsplit(void);
void	promote(NODE *);







/* Global functions -- awk4.c */
NODE	*f_exp(NODE *np);
NODE	*f_int(NODE *np);
NODE	*f_log(NODE *np);
NODE	*f_sqrt(NODE *np);
NODE	*f_getline(NODE *np);
NODE	*f_index(NODE *np);
NODE	*f_length(NODE *np);
NODE	*f_split(NODE *np);
NODE	*f_sprintf(NODE *np);
NODE	*f_substr(NODE *np);
NODE	*f_rand(NODE *np);
NODE	*f_srand(NODE *np);
NODE	*f_sin(NODE *np);
NODE	*f_cos(NODE *np);
NODE	*f_atan2(NODE *np);
NODE	*f_sub(NODE *np);
NODE	*f_gsub(NODE *np);
NODE	*f_match(NODE *np);
NODE	*f_system(NODE *np);
NODE	*f_ord(NODE *np);
NODE	*f_tolower(NODE *np);
NODE	*f_toupper(NODE *np);
NODE	*f_close(NODE *np);
NODE	*f_asort(NODE *np);

/* In awk0.c */



extern	wchar_t	_null[];
extern	char	r[];
extern	char	w[];
extern	wchar_t	s_OFMT[];
extern	wchar_t	s_CONVFMT[];
extern	wchar_t	s_NR[];
extern	wchar_t	s_NF[];
extern	wchar_t	s_OFS[];
extern	wchar_t	s_ORS[];
extern	wchar_t	s_RS[];
extern	wchar_t	s_FS[];
extern	wchar_t	s_FNR[];
extern	wchar_t	s_SUBSEP[];
extern	wchar_t	s_ARGC[], s_ARGV[], s_ENVIRON[];
extern	wchar_t	s_FILENAME[], s_SYMTAB[];
extern	wchar_t	s_BEGIN[], s_END[], s_next[];
extern	wchar_t	_begin[], _end[];
extern	wchar_t	s_exp[], s_getline[], s_index[], s_int[], s_length[], s_log[];
extern	wchar_t	s_split[], s_sprintf[], s_sqrt[], s_substr[];
extern	wchar_t	s_rand[], s_srand[], s_sin[], s_cos[], s_atan2[];
extern	wchar_t	s_sub[], s_gsub[], s_match[], s_system[], s_ord[];
extern	wchar_t	s_toupper[], s_tolower[], s_asort[];
extern	wchar_t	s_close[];
extern	wchar_t	redelim;
extern	unsigned char	inprint;
extern	unsigned char	funparm;
extern	unsigned char	splitdone;
extern	uint_t	npattern;
extern	uint_t	nfield;
extern	uint_t	fcount;
extern	uint_t	phase;
extern	uint_t	running;
extern	uchar_t	catterm;
extern	uint_t	lexlast;
extern	uint_t	lineno;
extern	uchar_t	needsplit, needenviron, doing_begin, begin_getline;
extern	ushort_t	slevel;
extern	ushort_t	loopexit;
extern	wchar_t	radixpoint;
extern	REGEXP	resep;
extern	RESERVED	reserved[];
extern	RESFUNC		resfuncs[];
extern	long	NIOSTREAM;	/* Maximum open I/O streams */
extern	OFILE	*ofiles;
extern	wchar_t	*linebuf;
extern	size_t	lbuflen;
extern	char	interr[];
extern	char	nomem[];
extern	NODE	*symtab[NBUCKET];
extern	NODE	*yytree;
extern	NODE	*freelist;
extern	wchar_t	*(*awkrecord)(wchar_t *, int, FILE *);
extern	wchar_t	*(*awkfield)(wchar_t **);

extern	NODE	*constant;
extern	NODE	*const0;
extern	NODE	*const1;
extern	NODE	*constundef;
extern	NODE	*field0;
extern	NODE	*incNR;
extern	NODE	*incFNR;
extern	NODE	*clrFNR;
extern	NODE	*ARGVsubi;
extern	NODE	*varNR;
extern	NODE	*varFNR;
extern	NODE	*varNF;
extern	NODE	*varOFMT;
extern	NODE	*varCONVFMT;
extern	NODE	*varOFS;
extern	NODE	*varORS;
extern	NODE	*varFS;
extern	NODE	*varRS;
extern	NODE	*varARGC;
extern	NODE	*varSUBSEP;
extern	NODE	*varENVIRON;
extern	NODE	*varSYMTAB;
extern	NODE	*varFILENAME;
extern	NODE	*curnode;
extern	NODE    *inc_oper;
extern	NODE	*asn_oper;

extern char *mbunconvert(wchar_t *);
extern	wchar_t 	*mbstowcsdup(char *);
extern	char		*wcstombsdup(wchar_t *);
extern	void		awkerr(char *, ...);
/*
 * The following defines the expected max length in chars of a printed number.
 * This should be the longest expected size for any type of number
 * ie. float, long etc. This number is used to calculate the approximate
 * number of chars needed to hold the number.
 */
#ifdef M_NUMSIZE
#define	NUMSIZE M_NUMSIZE
#else
#define	NUMSIZE 30
#endif

#define	M_MB_L(s)	L##s
#ifdef  __STDC__
#define	ANSI(x) x
#else
#define	const
#define	signed
#define	volatile
#define	ANSI(x) ()
#endif

#define	isWblank(x) (((x) == ' ' || (x) == '\t') ? 1 : 0)


/*
 * Wide character version of regular expression functions.
 */
#define	REGWMATCH_T	int_regwmatch_t
#define	REGWCOMP	int_regwcomp
#define	REGWEXEC	int_regwexec
#define	REGWFREE	int_regwfree
#define	REGWERROR	int_regwerror
#define	REGWDOSUBA	int_regwdosuba

typedef struct {
	const wchar_t	*rm_sp, *rm_ep;
	regoff_t	rm_so, rm_eo;
} int_regwmatch_t;

extern int int_regwcomp(REGEXP *, const wchar_t *);
extern int int_regwexec(REGEXP, const wchar_t *, size_t,
			int_regwmatch_t *, int);
extern void int_regwfree(REGEXP);
extern size_t int_regwerror(int, REGEXP, char *, size_t);
extern int int_regwdosuba(REGEXP, const wchar_t *,
			const wchar_t *, wchar_t **, int, int *);
